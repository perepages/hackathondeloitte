"""Motor de reglas del N1: respaldo del LLM en verdict.py (y lo único que decide con SOC_VERDICT_ENGINE=rules).

Junta dos trabajos del equipo:
  1. Reglas de los runbooks RB-01…RB-10 de Marc Pozo (rama pozobranch, «Veredicte implementat»), con estos
     errores corregidos:
       - inteligencia: solo cuenta como maliciosa la reputación malicious/suspicious (antes, cualquier dato, incluso
         «known-good», marcaba ataque real y proponía bloquear Teams);
       - cambio aprobado: la alerta debe caer dentro de la ventana del cambio y, si el cambio fija IPs de origen,
         venir de ellas (antes cerraba un túnel DNS por una actualización del WMS de otro día);
       - pentest: lo cubre la regla de cambios (CHG-2026-1042, IPs 192.0.2.10-12), no «cualquier WAF del 8 al 10»;
       - simulacro: «simulacro» en el asunto Y remitente interno (antes bastaba la palabra en cualquier campo);
       - SCCM: proceso padre CcmExec Y usuario SYSTEM (antes bastaba «sccm» en cualquier campo);
       - viaje de RRHH: ciudad y fechas del viaje deben coincidir con el inicio de sesión;
       - robo de cuenta (ATO): por rule_id (antes `"ato" in rule_name` encajaba con «dato», «contrato»…);
       - asistente Vela: primero se buscan indicios de manipulación (antes toda frase corta era falsa alarma);
       - Excel → SAP firmado por SAP SE es autorizado; persistencia sin firma, ataque.
  2. Reglas por caso de uso de scripts/nivel1_triage.py, para lo que los runbooks no resuelven.

Devuelve una propuesta con la misma forma que la del LLM; verdict.decide aplica la política encima.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

KNOWN_GOOD = ("known-good", "benign")
BAD_REPUTATION = ("malicious", "suspicious")
BENIGN_DOMAINS = ("microsoft.com", "googleapis.com", "google.com", "amazonaws.com", "cloudfront.net",
                  "windows.net", "akamaized.net", "azureedge.net", "cdn77.example", "office.com")
INJECTION_HINTS = re.compile(
    r"(system prompt|prompt de sistema|instrucciones|ignora (todas|tus|las)|olvida (tus|las)|modo (admin|desarrollador)|"
    r"descuento|otro cliente|pedidos de|api key|contraseña|<\s*script|jailbreak)", re.I)


# ----------------------------------------------------------------------------- utilidades

def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _madrid_to_utc(value: str | None) -> datetime | None:
    """Las horas de calendario_cambios.csv son de España (las alertas, UTC). Horario de verano de la UE: UTC+2
    desde el último domingo de marzo hasta el último domingo de octubre (01:00 UTC); UTC+1 el resto."""
    if not value:
        return None
    try:
        local = datetime.fromisoformat(str(value).replace(" ", "T"))
    except ValueError:
        return None
    if local.tzinfo:
        return local

    def last_sunday(month: int) -> datetime:
        day = datetime(local.year, month, 31 if month in (3, 10) else 30)
        return day.replace(day=day.day - (day.weekday() + 1) % 7)

    summer_start, summer_end = last_sunday(3).replace(hour=2), last_sunday(10).replace(hour=3)
    offset = 2 if summer_start <= local < summer_end else 1
    return (local - timedelta(hours=offset)).replace(tzinfo=timezone.utc)


def _ctx(preview: dict, kind: str) -> list[dict]:
    return [c["data"] for c in preview.get("contexts") or [] if c.get("kind") == kind and isinstance(c.get("data"), dict)]


def _first_upn(alert: dict) -> str:
    users = (alert.get("entities") or {}).get("users") or []
    return next((u.get("upn") for u in users if isinstance(u, dict) and "@" in str(u.get("upn", ""))), "")


def _first_host(alert: dict) -> str:
    hosts = (alert.get("entities") or {}).get("hosts") or []
    return next((h.get("hostname") for h in hosts if isinstance(h, dict) and h.get("hostname")), "")


def _domain_ok(domain: str) -> bool:
    d = domain.lower()
    return any(d == b or d.endswith("." + b) for b in BENIGN_DOMAINS)


def tip_matches(preview: dict, reputations=BAD_REPUTATION) -> list[tuple[str, dict]]:
    out = []
    for c in preview.get("contexts") or []:
        tip = (c.get("data") or {}).get("tip") if c.get("kind") == "intel" else None
        if isinstance(tip, dict) and str(tip.get("reputation", "")).lower() in reputations:
            out.append((c["key"], tip))
    return out


def _tip_text(matches: list[tuple[str, dict]]) -> str:
    return "; ".join(f"{k} = {t.get('reputation')} ({t.get('tags') or t.get('malware_family') or 'sense etiqueta'}, "
                     f"confiança {t.get('confidence')})" for k, t in matches)


def _ips_in(text: str) -> list:
    """IPs y rangos que cita un cambio: «192.0.2.10-12», «10.0.0.0/24», «198.51.100.7»."""
    nets = []
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})(?:-(\d{1,3})|/(\d{1,2}))?", text or ""):
        base, last, mask = m.groups()
        try:
            if mask:
                nets.append(ipaddress.ip_network(f"{base}/{mask}", strict=False))
            elif last:
                start = ipaddress.ip_address(base)
                nets += [ipaddress.ip_address(f"{base.rsplit('.', 1)[0]}.{n}")
                         for n in range(int(str(start).rsplit('.', 1)[1]), int(last) + 1)]
            else:
                nets.append(ipaddress.ip_address(base))
        except ValueError:
            continue
    return nets


def _ip_matches(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else addr == n for n in nets)


def authorized_change(preview: dict) -> dict | None:
    """Cambio aprobado que cubre la alerta: misma ventana temporal (calendario en hora de España) y, si el cambio
    fija IPs de origen, una de ellas."""
    alert = preview["alert"]
    when = _dt(alert.get("created_at"))
    if when is None:
        return None
    alert_ips = [str(i) for i in (alert.get("entities") or {}).get("ips") or []]
    for change in _ctx(preview, "change"):
        start, end = _madrid_to_utc(change.get("inicio")), _madrid_to_utc(change.get("fin"))
        if not (start and end and start <= when <= end):
            continue
        nets = _ips_in(f"{change.get('detalle', '')} {change.get('alcance', '')}")
        if nets and not any(_ip_matches(ip, nets) for ip in alert_ips):
            continue
        return change
    return None


def _travel_matches(alert: dict, users: list[dict]) -> str | None:
    """Viaje comunicado a RRHH que explica el inicio de sesión: misma ciudad y fecha dentro del viaje."""
    login = (alert.get("evidence") or {}).get("current_login") or {}
    city = str(login.get("city", "")).lower() if isinstance(login, dict) else ""
    when = _dt(alert.get("created_at"))
    if not city or when is None:
        return None
    for user in users:
        for hr in user.get("hr_events") or []:
            detail = str(hr.get("detalle", ""))
            if "viaje" not in str(hr.get("tipo", "")).lower() or city not in detail.lower():
                continue
            m = re.search(r"del (\d{1,2})/(\d{1,2}) al (\d{1,2})/(\d{1,2})", detail)
            if m:
                d1, m1, d2, m2 = map(int, m.groups())
                year = when.year
                if not (datetime(year, m1, d1, tzinfo=timezone.utc) <= when
                        <= datetime(year, m2, d2, 23, 59, tzinfo=timezone.utc)):
                    continue
            return f"{hr.get('tipo')}: {detail}"
    return None


def _proposal(verdict: str, confidence: float, why: str, source: str, *, adjustment: int = 0,
              decision: str | None = None, actions: list | None = None, title: str = "") -> dict:
    return {"verdict": verdict, "confidence": confidence, "severity_adjustment": adjustment, "decision": decision,
            "title": title, "summary": why, "justification": why, "recommended_actions": actions,
            "injection_detected": False, "rule": source}


# ----------------------------------------------------------------------------- runbooks (Marc, corregidos)

def runbooks(preview: dict) -> dict | None:
    alert = preview["alert"]
    ev, ent = alert.get("evidence") or {}, alert.get("entities") or {}
    rule = alert.get("rule_id") or ""
    upn, host = _first_upn(alert), _first_host(alert)
    users = _ctx(preview, "user")

    # --- actividad autorizada
    subject, sender = str(ev.get("subject", "")), str(ev.get("sender", "")).lower()
    if "simulacro" in subject.lower() and sender.endswith("@tarvia.example"):
        return _proposal("benign_true_positive", 0.95, f"Correu del simulacre intern de phishing («{subject}», "
                         f"remitent {sender}): l'usuari el va reportar bé (RB-01).", "RB-01 simulacre")

    if change := authorized_change(preview):
        return _proposal("benign_true_positive", 0.9, f"L'alerta cau dins del canvi aprovat {change.get('id')} "
                         f"«{change.get('titulo')}» ({change.get('inicio')} – {change.get('fin')} hora d'Espanya; "
                         f"{change.get('detalle')}).",
                         "Calendari de canvis")

    if "ccmexec" in str(ev.get("parent", "")).lower() and str(ev.get("user", "")).upper() == "SYSTEM":
        return _proposal("benign_true_positive", 0.9, "PowerShell codificat llançat per l'agent SCCM (CcmExec.exe) "
                         "com a SYSTEM: tasca d'inventari de programari (RB-02).", "RB-02 SCCM")

    if "eicar" in str(ev.get("detection_name", "")).lower():
        return _proposal("benign_true_positive", 0.9, f"Fitxer de prova d'antivirus EICAR "
                         f"({ev.get('detection_name')}), {ev.get('action', 'detectat')}: no és programari maliciós real (RB-02).",
                         "RB-02 EICAR")

    if rule == "UC-IDP-001" and (travel := _travel_matches(alert, users)):
        return _proposal("benign_true_positive", 0.85, f"Inici de sessió explicat per un viatge comunicat a RRHH "
                         f"({travel}) (RB-03).", "RB-03 viatge")

    if rule.startswith("UC-DLP"):
        if "gestoria-pons.example" in str(ev).lower():
            return _proposal("benign_true_positive", 0.9, "Enviament de nòmines a la gestoria externa autoritzada "
                             "(gestoria-pons.example), flux de negoci aprovat (RB-04).", "RB-04 flux aprovat")
        if str(ev.get("personal_data_matches")) == "0":
            return _proposal("benign_true_positive", 0.7, "Pujada a un servei extern sense dades personals "
                             "(0 coincidències al DLP): sense impacte RGPD (RB-04).", "RB-04 sense dades personals")

    tree = str(ev.get("process_tree", ""))
    if rule == "UC-EDR-001" and ev.get("signer") and tree.lower().endswith("saplogon.exe"):
        return _proposal("benign_true_positive", 0.85, f"{tree} signat per {ev['signer']}: integració Excel-SAP "
                         "habitual.", "RB-02 Excel-SAP")

    # --- ataque real
    for sbx in _ctx(preview, "sandbox"):
        score = sbx.get("score") or sbx.get("threat_score") or 0
        if str(sbx.get("verdict", "")).lower() in ("malicious", "malware") or (isinstance(score, (int, float)) and score >= 70):
            family = sbx.get("family") or sbx.get("malware_family") or "malware"
            executed = str(ev.get("executed")).lower() == "true"
            acts = [{"action": "block_ioc", "target": sbx.get("sha256", ""), "justification": f"Hash maliciós ({family})."}]
            if host:
                acts.append({"action": "isolate_host", "target": host, "justification": "Programari maliciós verificat a la sandbox."})
            return _proposal("true_positive", 0.9, f"La sandbox confirma programari maliciós ({family}, puntuació {score})"
                             + (" i es va arribar a executar." if executed else ".") + " (RB-02)", "RB-02 sandbox",
                             adjustment=1 if executed else 0, decision="escalate" if executed else None, actions=acts)

    if rule == "UC-EML-003":
        acts = [{"action": "block_ioc", "target": d, "justification": "Domini de phishing."}
                for d in (ent.get("domains") or [])[:2]]
        if upn:
            acts += [{"action": "revoke_sessions", "target": upn, "justification": "Possible robatori de credencials."},
                     {"action": "reset_password", "target": upn, "justification": "Forçar el canvi de contrasenya."}]
        return _proposal("true_positive", 0.85, "L'empleat va fer clic en un enllaç que el filtre de correu "
                         "va reclassificar com a phishing: possible robatori de credencials (RB-01).", "RB-01 clic en phishing",
                         adjustment=1, decision="escalate", actions=acts)

    if rule == "UC-EDR-001" and ev.get("persistence") and not ev.get("signer"):
        acts = [{"action": "isolate_host", "target": host, "justification": "Execució amb persistència."}] if host else []
        return _proposal("true_positive", 0.9, f"Cadena {tree} sense signatura amb persistència ({ev['persistence']}) i "
                         f"l'EDR només la va detectar ({ev.get('edr_action', '')}): execució confirmada (RB-02).",
                         "RB-02 persistència", adjustment=1, decision="escalate", actions=acts)

    if rule == "UC-IDP-003" and re.search(r"approved|aprobad", str(ev.get("final_result", "")), re.I) and upn:
        return _proposal("true_positive", 0.9, "Fatiga MFA: després de desenes de notificacions l'usuari en va aprovar una "
                         "(accés confirmat) (RB-03).", "RB-03 fatiga MFA", adjustment=1, decision="escalate",
                         actions=[{"action": "revoke_sessions", "target": upn, "justification": "MFA eludit."},
                                  {"action": "reset_password", "target": upn, "justification": "Contrasenya compromesa."}])

    if rule == "UC-IDP-002" and isinstance(ev.get("successes"), (int, float)) and ev["successes"] > 0:
        acts = [{"action": "block_ioc", "target": ip, "justification": "Origen del password spraying."}
                for ip in (ent.get("ips") or [])[:6]]
        return _proposal("true_positive", 0.9, f"Password spraying amb {ev['successes']} accés(sos) vàlid(s) "
                         f"({ev.get('failed_attempts')} intents contra {ev.get('distinct_accounts')} comptes) (RB-03).",
                         "RB-03 password spraying", adjustment=1, decision="escalate", actions=acts)

    if rule == "UC-VPN-001" and str(ev.get("account_type", "")).lower() == "external":
        usual, src = str(ev.get("usual_src", "")), str(ev.get("src_asn", ""))
        new_origin = bool(src) and src.lower() not in usual.lower()
        local = str(ev.get("local_time", ""))
        weekend = local[:3].lower() in ("sat", "sun", "sáb", "dom")
        hour = int(m.group(1)) if (m := re.search(r"(\d{1,2}):\d{2}", local)) else None
        off_hours = weekend or (hour is not None and not 8 <= hour < 18)
        connected = bool(re.search(r"aprobad|approved|connect", str(ev), re.I))
        if new_origin and off_hours and connected:
            ips = (ent.get("ips") or [])[:1]
            return _proposal("true_positive", 0.8, f"Compte de proveïdor connectat per VPN fora de la seva finestra "
                             f"contractual ({ev.get('contract_window')}; connexió: {local}) des de {src}, que no és el seu "
                             f"origen habitual ({usual}), amb MFA aprovat i sense cap canvi que ho cobreixi: sessió des "
                             "d'infraestructura aliena, possible robatori de credencials del proveïdor (RB-03).",
                             "RB-03 VPN de proveïdor", adjustment=1, decision="escalate",
                             actions=([{"action": "revoke_sessions", "target": upn, "justification": "Sessió sospitosa."},
                                       {"action": "reset_password", "target": upn, "justification": "Credencials del "
                                        "proveïdor possiblement robades."}] if upn else [])
                             + [{"action": "block_ioc", "target": ip, "justification": "Origen no habitual."} for ip in ips])

    if rule == "UC-WEB-003":
        acts = [{"action": "block_ioc", "target": ip, "justification": "Origen del robatori de compte."}
                for ip in (ent.get("ips") or [])[:2]]
        return _proposal("true_positive", 0.9, f"Robatori de compte de client amb frau: {ev.get('sequence', 'seqüència ATO')} "
                         f"en {ev.get('minutes_between', '?')} min (RB-05). Frau econòmic: escalat obligatori.",
                         "RB-05 ATO", decision="escalate", actions=acts)

    zones = [str(a.get("zone", "")) for a in _ctx(preview, "asset")]
    if rule.startswith("UC-OT") or any(z.upper().endswith("-OT") for z in zones):
        if host and host.upper() not in ("ENG-WS01", "WMS01"):
            return _proposal("true_positive", 0.85, f"Connexió a la xarxa OT des de {host}; només ENG-WS01 i WMS01 hi estan "
                             "autoritzats (RB-08). No s'actua sobre OT: s'escala a Operacions.", "RB-08 OT",
                             decision="escalate", actions=[])

    if rule == "UC-NET-006":  # túnel DNS (RB-09: «software conocido → cerrar»)
        age, clients = ev.get("domain_age_days"), ev.get("distinct_clients")
        parent = str(ev.get("parent_domain") or next(iter(ent.get("domains") or []), ""))
        if (isinstance(age, (int, float)) and age >= 365 and isinstance(clients, (int, float)) and clients >= 20
                and not tip_matches(preview)):
            # Antivirus y listas antispam (McAfee GTI, Sophos, Spamhaus…) consultan por DNS con subdominios largos.
            # Un túnel de un atacante usa un dominio nuevo desde uno o dos equipos, no uno de años desde decenas.
            p = _proposal("false_positive", 0.9, f"Consultes llargues a {parent}, domini de {int(age)} dies que fan "
                          f"servir {int(clients)} equips diferents i sense mala reputació: és el patró d'un programari "
                          "de seguretat conegut (consultes de reputació per DNS), no un túnel (RB-09: programari "
                          "conegut → tancar i proposar una exclusió a la regla).", "RB-09 programari conegut")
            p["firm"] = True  # criterio objetivo del runbook: prevalece sobre la IA (verdict.decide)
            return p
        if isinstance(age, (int, float)) and age < 90 and isinstance(clients, (int, float)) and clients <= 2:
            return _proposal("true_positive", 0.85, f"{ev.get('queries_1h', 'Moltes')} consultes en 1 h amb etiquetes "
                             f"llargues a {parent}, domini de {int(age)} dies que només fa servir aquest equip: "
                             "possible exfiltració per DNS (RB-09).", "RB-09 túnel DNS", decision="escalate",
                             actions=[{"action": "block_ioc", "target": parent, "justification": "Possible túnel DNS."}]
                             + ([{"action": "isolate_host", "target": host, "justification": "Possible exfiltració."}]
                                if host else []))

    if rule in ("UC-NET-001", "UC-NET-005"):
        domain = str(ev.get("domain") or ev.get("parent_domain") or next(iter(ent.get("domains") or []), ""))
        good = tip_matches(preview, KNOWN_GOOD)
        if good and not tip_matches(preview):
            return _proposal("false_positive", 0.85, f"Trànsit periòdic cap a un servei legítim segons el TIP "
                             f"({_tip_text(good)}) (RB-09).", "RB-09 servei legítim")
        age = ev.get("domain_age_days")
        if rule == "UC-NET-001" and isinstance(age, (int, float)) and age < 30 and not _domain_ok(domain):
            return _proposal("true_positive", 0.85, f"Beaconing amb poca variància cap a {domain}, domini de {age} dies "
                             "sense historial: possible C2 (RB-09).", "RB-09 domini jove", decision="escalate",
                             actions=[{"action": "block_ioc", "target": domain, "justification": "Possible C2."}]
                             + ([{"action": "isolate_host", "target": host, "justification": "Possible implant."}]
                                if host else []))
    return None


# ----------------------------------------------------------------------------- reglas por caso de uso (nuestras)

def use_case_rules(preview: dict) -> dict:
    from scripts import nivel1_triage as reglas
    import soc_api
    reglas.API = soc_api.BASE_URL
    alert = preview["alert"]
    ctx = {"assets": _ctx(preview, "asset"), "users": _ctx(preview, "user"),
           "intel": {c["key"]: c["data"] for c in preview.get("contexts") or [] if c.get("kind") == "intel"},
           "notes": []}
    bad = reglas.bad_intel(ctx)
    rule = reglas.RULES.get(alert.get("rule_id"), reglas.r_default)
    if alert.get("rule_id") == "UC-AI-001":  # primero, indicios de manipulación del asistente
        excerpt = str((alert.get("evidence") or {}).get("prompt_excerpt", ""))
        if INJECTION_HINTS.search(excerpt):
            return _proposal("true_positive", 0.75, f"Intent de manipular l'assistent Vela: «{excerpt[:100]}» (RB-07).",
                             "RB-07 manipulació")
    try:
        verdict, confidence, why, bump = rule(alert, ctx, bad)
    except Exception as exc:  # una regla que no sabe leer esta alerta no debe tumbar el triaje
        verdict, confidence, why, bump = reglas.r_default(alert, ctx, bad)
        why += f" (La regla específica ha fallat: {exc}.)"
    return _proposal(verdict, confidence, why, f"{alert.get('rule_id')} (regles per cas d'ús)", adjustment=bump)


def evaluate(preview: dict) -> dict:
    """Propuesta de las reglas: primero los runbooks; si no resuelven, las reglas por caso de uso."""
    alert = preview["alert"]
    proposal = runbooks(preview) or use_case_rules(preview)
    if proposal["verdict"] == "needs_more_info" and (bad := tip_matches(preview)):
        proposal = _proposal("true_positive", 0.7, f"Indicadors amb mala reputació al TIP: {_tip_text(bad)}.",
                             "TIP", actions=[{"action": "block_ioc", "target": k, "justification": "Mala reputació al TIP."}
                                             for k, _ in bad])
    if not proposal["title"]:
        proposal["title"] = f"{alert.get('rule_name')}: {proposal['justification'].split('.')[0][:90]}"
    return proposal
