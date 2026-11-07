import unicodedata


SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
# Nombres en catalán para los textos que ve la persona (la interfaz está en catalán)
SEVERITY_CA = {"informational": "informativa", "low": "baixa", "medium": "mitjana", "high": "alta",
               "critical": "crítica"}
CRITICALITY_CA = {"baja": "Baixa", "media": "Mitjana", "alta": "Alta", "critica": "Crítica"}


def criticality_ca(value: str | None) -> str:
    """Criticidad de la CMDB (en castellano) con el nombre en catalán para la interfaz."""
    return CRITICALITY_CA.get(_normalize(str(value or "")), str(value or ""))
CRITICALITY_ORDER = ("baja", "media", "alta", "critica")

# Operational severity matrix from 01_contexto/politica_soc.md.
_MATRIX = {
    "informational": ("informational", "informational", "low", "low"),
    "low": ("informational", "low", "low", "medium"),
    "medium": ("low", "medium", "medium", "high"),
    "high": ("medium", "high", "high", "critical"),
    "critical": ("high", "critical", "critical", "critical"),
}


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.strip().lower())
    return "".join(char for char in normalized if not unicodedata.combining(char))


def base_severity(rule_severity: str, asset_criticality: str) -> str:
    """Cross the SIEM rule severity with the most critical affected asset."""
    rule = _normalize(rule_severity)
    criticality = _normalize(asset_criticality)
    if rule not in _MATRIX:
        raise ValueError(f"Severidad de regla desconocida: {rule_severity!r}")
    try:
        column = CRITICALITY_ORDER.index(criticality)
    except ValueError as exc:
        raise ValueError(f"Criticidad de activo desconocida: {asset_criticality!r}") from exc
    return _MATRIX[rule][column]


# Activo afectado cuando la alerta no nombra un equipo (02_inventario/servicios_negocio.csv y activos.csv).
# La matriz se cruza con «el activo o identidad más crítica afectada»: para una alerta contra la tienda online, el
# activo es la tienda aunque la alerta solo traiga la IP del atacante.
SERVICE_ASSET_BY_PRODUCT = {
    "WAF": ("WEB-ECOM01", "frontal de la botiga en línia, servei «Tienda online y app»"),
    "ECOM": ("WEB-ECOM01", "frontal de la botiga en línia, servei «Tienda online y app»"),
    "AI_GATEWAY": ("AI-ASSIST01", "backend de l'assistent de compra «Vela»"),
}
STORE_DOMAINS = ("tarvia.example",)
# Buckets y servicios sin ficha en la CMDB, con la criticidad de servicios_negocio.csv
SERVICE_CRITICALITY = {
    "tarvia-backups-prod": ("Alta", "Copias de seguridad"),
}


def service_assets(alert: dict) -> list[tuple[str, str]]:
    """(hostname de la CMDB, por qué es el activo afectado) para alertas que no nombran un equipo."""
    out = []
    product = str(alert.get("source_product", "")).upper()
    if product in SERVICE_ASSET_BY_PRODUCT:
        out.append(SERVICE_ASSET_BY_PRODUCT[product])
    entities = alert.get("entities") or {}
    for url in entities.get("urls") or []:
        host = str(url).split("://", 1)[-1].split("/", 1)[0].lower()
        if any(host == d or host.endswith("." + d) for d in STORE_DOMAINS):
            out.append(SERVICE_ASSET_BY_PRODUCT["WAF"])
    if entities.get("customers") and product not in SERVICE_ASSET_BY_PRODUCT:
        out.append(SERVICE_ASSET_BY_PRODUCT["ECOM"])
    return list(dict.fromkeys(out))


def cloud_asset(alert: dict) -> dict | None:
    """Ficha de un recurso cloud: criticidad declarada en la alerta o, si no, la del servicio de negocio."""
    cloud = (alert.get("entities") or {}).get("cloud") or {}
    bucket = cloud.get("bucket") if isinstance(cloud, dict) else None
    if not bucket:
        return None
    declared = str((alert.get("evidence") or {}).get("bucket_classification", ""))
    for level in ("Crítica", "Alta", "Media", "Baja"):
        if _normalize(declared).startswith(_normalize(level)):
            return {"hostname": bucket, "criticality": level, "business_service": declared,
                    "zone": "cloud", "_origen": "classificació del bucket a l'alerta"}
    if bucket in SERVICE_CRITICALITY:
        level, service = SERVICE_CRITICALITY[bucket]
        return {"hostname": bucket, "criticality": level, "business_service": service,
                "zone": "cloud", "_origen": "servicios_negocio.csv"}
    return None


def apply_severity_adjustment(severity: str, adjustment: int) -> str:
    """Apply at most one policy adjustment (+1, -1, or 0), clamped to bounds."""
    normalized = _normalize(severity)
    if normalized not in SEVERITY_ORDER:
        raise ValueError(f"Severidad desconocida: {severity!r}")
    if adjustment not in (-1, 0, 1):
        raise ValueError("El ajuste de severidad debe ser -1, 0 o 1")
    index = SEVERITY_ORDER.index(normalized)
    adjusted_index = max(0, min(len(SEVERITY_ORDER) - 1, index + adjustment))
    return SEVERITY_ORDER[adjusted_index]
