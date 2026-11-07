from datetime import datetime, timedelta, timezone
import re

import soc_api
from policy import CRITICALITY_ORDER, apply_severity_adjustment, base_severity, cloud_asset, service_assets
from schemas import Alert, ContextRecord, QueryRecord, TriagePreview


_PRODUCT_TO_LOG_SOURCE = {
    "AD": "ad_events",
    "AI_GATEWAY": "ai_gateway",
    "CICD": "cicd_builds",
    "CLOUD": "cloudtrail",
    "DLP": "dlp",
    "DNS": "dns",
    "ECOM": "ecom_auth",
    "EDR": "edr_events",
    "EMAIL_GW": "email",
    "IDP": "idp_signins",
    "NGFW": "firewall",
    "PROXY": "proxy",
    "VPN": "vpn",
    "WAF": "waf",
}


def _items(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first(record, *keys):
    if isinstance(record, str):
        return record
    if isinstance(record, dict):
        for key in keys:
            value = record.get(key)
            if value:
                return str(value)
    return None


def _truthy(value) -> bool:
    return value is True or str(value).strip().lower() in {"true", "1", "yes", "si", "sí"}


def _result_count(data) -> int:
    if isinstance(data, dict):
        if isinstance(data.get("count"), int):
            return data["count"]
        if isinstance(data.get("items"), list):
            return len(data["items"])
        return 1
    return len(data) if isinstance(data, list) else 1


def _window(created_at: str | None) -> tuple[str, str]:
    if not created_at:
        return "", ""
    try:
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return (
            (timestamp - timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            (timestamp + timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        )
    except ValueError:
        return "", ""


def _criticality_rank(value: str) -> int:
    normalized = value.strip().lower().replace("í", "i")
    try:
        return CRITICALITY_ORDER.index(normalized)
    except ValueError:
        return -1


def analyze_alert(alert_id: str, decide: bool = True) -> TriagePreview:
    """Recoge evidencias acotadas y, si `decide`, propone veredicto, decisión y acciones (verdict.decide).

    La propuesta la da el LLM (assistant.decide_json) con las reglas de scripts/nivel1_triage.py como red de
    seguridad, y la política SOC se aplica siempre encima. La decisión final es de una persona."""
    raw_alert = soc_api.get_alert(alert_id)
    alert = Alert.model_validate(raw_alert)
    contexts: list[ContextRecord] = []
    related_logs: list[dict] = []
    queries: list[QueryRecord] = []
    open_questions: list[str] = []

    def fetch(path: str, params: dict, key: str, function):
        try:
            result = function()
        except soc_api.SocAPIError as exc:
            status = "not_found" if exc.status_code == 404 else "error"
            queries.append(
                QueryRecord(
                    path=path,
                    params=params,
                    status=status,
                    note=str(exc),
                )
            )
            return None
        except Exception as exc:
            queries.append(
                QueryRecord(path=path, params=params, status="error", note=str(exc))
            )
            return None
        queries.append(
            QueryRecord(
                path=path,
                params=params,
                status="ok",
                result_count=_result_count(result),
            )
        )
        return result

    entities = alert.entities
    assets: list[dict] = []
    asset_origin: dict[str, str] = {}  # hostname -> por qué cuenta como activo afectado

    def add_asset(hostname: str, ip: str | None = None, origin: str = "equipo de la alerta") -> None:
        if hostname in asset_origin:
            return
        asset = fetch(f"/assets/{hostname}", {}, hostname, lambda h=hostname: soc_api.get_asset(h))
        if asset is None and ip and ip != hostname:
            asset = fetch(f"/assets/{ip}", {}, ip, lambda address=ip: soc_api.get_asset(address))
        if isinstance(asset, dict):
            asset_origin[hostname] = origin
            assets.append(asset)
            contexts.append(ContextRecord(kind="asset", key=hostname, data=asset))
            changes = fetch(
                "/changes",
                {"q": hostname},
                hostname,
                lambda h=hostname: soc_api.search_changes(h),
            )
            if isinstance(changes, list) and changes:
                contexts.extend(
                    ContextRecord(kind="change", key=hostname, data=change)
                    for change in changes[:10]
                )

    for host in _items(entities.get("hosts"))[:5]:
        hostname = _first(host, "hostname", "host", "ip")
        if hostname:
            add_asset(hostname, _first(host, "ip"))

    users: list[dict] = []
    for user in _items(entities.get("users"))[:5]:
        key = _first(user, "upn", "username", "user")
        if not key:
            continue
        result = fetch(f"/users/{key}", {}, key, lambda k=key: soc_api.get_user(k))
        if isinstance(result, dict):
            users.append(result)
            contexts.append(ContextRecord(kind="user", key=key, data=result))

    # Cambios que la propia alerta cita (p. ej. evidence.change_ticket = CHG-2026-1078)
    cited = re.findall(r"CHG-\d{4}-\d+", f"{alert.description} {alert.evidence}")
    known = {c.data.get("id") for c in contexts if c.kind == "change"}
    for change_id in dict.fromkeys(cited):
        if change_id in known:
            continue
        found = fetch("/changes", {"q": change_id}, change_id, lambda q=change_id: soc_api.search_changes(q))
        for change in found if isinstance(found, list) else []:
            if change.get("id") == change_id:
                contexts.append(ContextRecord(kind="change", key=change_id, data=change))

    # Activo afectado cuando la alerta no trae un equipo: el puesto del usuario, el servicio atacado o el bucket
    if not assets:
        for user in users:
            if user.get("workstation"):
                add_asset(str(user["workstation"]), origin=f"puesto de trabajo de {user.get('upn')}")
        for hostname, origin in service_assets(alert.model_dump()):
            add_asset(hostname, origin=origin)
        cloud = cloud_asset(alert.model_dump())
        if cloud:
            asset_origin[cloud["hostname"]] = cloud["_origen"]
            assets.append(cloud)
            contexts.append(ContextRecord(kind="asset", key=cloud["hostname"], data=cloud))

    indicators: list[tuple[str, str]] = []
    for kind in ("ips", "domains"):
        indicators.extend((kind[:-1], value) for value in _items(entities.get(kind)) if isinstance(value, str))
    # Indicadores que solo vienen en la evidencia (remitente de un correo, dominio de beaconing o DGA)
    sender = alert.evidence.get("sender")
    if isinstance(sender, str) and "@" in sender:
        indicators.append(("domain", sender.split("@", 1)[1].strip().lower()))
    for key in ("domain", "parent_domain"):
        if isinstance(alert.evidence.get(key), str) and alert.evidence[key]:
            indicators.append(("domain", alert.evidence[key]))
    for indicator_type, indicator in dict.fromkeys(indicators):
        if len([item for item in contexts if item.kind == "intel"]) >= 10:
            break
        result = fetch(
            f"/intel/{indicator}",
            {},
            indicator,
            lambda value=indicator: soc_api.get_intel(value),
        )
        if isinstance(result, dict):
            contexts.append(ContextRecord(kind="intel", key=indicator, data=result))
            if result.get("tip") is None and result.get("geo") is None:
                open_questions.append(
                    f"No hay resultado de inteligencia para {indicator}; esto no confirma que sea benigno."
                )

    evidence_hashes = []
    for key in ("sha256", "hash"):
        value = alert.evidence.get(key)
        if isinstance(value, str):
            evidence_hashes.append(value)
    for file_item in _items(entities.get("files")):
        value = _first(file_item, "sha256", "hash")
        if value:
            evidence_hashes.append(value)
    for sha256 in dict.fromkeys(evidence_hashes):
        if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
            continue
        result = fetch(
            f"/sandbox/{sha256}",
            {},
            sha256,
            lambda value=sha256: soc_api.get_sandbox(value),
        )
        if isinstance(result, dict):
            contexts.append(ContextRecord(kind="sandbox", key=sha256, data=result))

    log_source = _PRODUCT_TO_LOG_SOURCE.get(alert.source_product.upper())
    since, until = _window(alert.created_at)
    if log_source:
        for event_id in alert.related_events[:5]:
            params = {"q": event_id, "desde": since, "hasta": until, "limit": 5}
            result = fetch(
                f"/logs/{log_source}",
                params,
                event_id,
                lambda e=event_id: soc_api.search_logs(
                    log_source, query=e, since=since, until=until, limit=5
                ),
            )
            if isinstance(result, dict):
                for event in result.get("items", []):
                    related_logs.append({"_source": log_source, **event})
    elif alert.related_events:
        open_questions.append(
            f"No hay correspondencia de fuente de logs configurada para {alert.source_product}."
        )

    if assets:
        most_critical_asset = max(
            assets,
            key=lambda asset: _criticality_rank(str(asset.get("criticality", ""))),
        )
        criticality = str(most_critical_asset.get("criticality", ""))
        hostname = str(most_critical_asset.get("hostname", "desconocido"))
        if _criticality_rank(criticality) >= 0:
            severity = base_severity(alert.severity, criticality)
            origin = asset_origin.get(hostname)
            rationale = (
                f"Matriz SOC: regla {alert.severity.lower()} × criticidad {criticality} del activo {hostname}"
                + (f" ({origin})" if origin and origin != "equipo de la alerta" else "")
                + f" = {severity}."
            )
        else:
            severity = base_severity(alert.severity, "Media")
            rationale = (f"Matriz SOC: la CMDB no da una criticidad reconocida para {hostname}; se asume Media: "
                         f"regla {alert.severity.lower()} × Media = {severity}.")
            open_questions.append("Confirmar la criticidad del activo antes de cerrar la severidad final.")
    else:
        severity = base_severity(alert.severity, "Media")
        rationale = (
            f"Matriz SOC: no se identificó ningún activo afectado en la CMDB; se asume criticidad Media: "
            f"regla {alert.severity.lower()} × Media = {severity}."
        )
        open_questions.append("Determinar la criticidad del activo o identidad afectada.")

    matrix_severity, matrix_rationale = severity, rationale
    privileged_identity = any(
        _truthy(user.get("vip")) or _truthy(user.get("privileged")) for user in users
    )
    if privileged_identity:
        severity = apply_severity_adjustment(severity, 1)
        rationale += " Ajuste +1 por identidad VIP o privilegiada (política SOC)."

    if not related_logs:
        open_questions.append("Corroborar si hubo actividad posterior o impacto efectivo.")

    preview = TriagePreview(
        alert=alert,
        contexts=contexts,
        related_logs=related_logs,
        queries=queries,
        verdict="needs_more_info",
        severity=severity,
        severity_rationale=rationale,
        open_questions=list(dict.fromkeys(open_questions)),
    )
    if not decide:
        return preview
    import verdict  # aquí para evitar el import circular (verdict usa los modelos de este módulo)

    return verdict.decide(
        preview,
        matrix_severity=matrix_severity,
        matrix_rationale=matrix_rationale,
        privileged_identity=privileged_identity,
    )
