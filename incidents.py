"""Incidentes (nivel 2 del reto): alertas DISTINTAS que forman parte de la misma intrusión, en un único ticket.

Lo piden las instrucciones de Deloitte:
  - politica_soc.md §1.4  «Correlacionar con otras alertas y logs de las mismas entidades».
  - politica_soc.md §5    escalar «varias alertas que, juntas, describen una cadena de ataque aunque cada una por
                          separado sea baja».
  - politica_soc.md §6    «varias alertas sobre la misma intrusión se documentan en un único ticket con todos los
                          alert_ids… diez tickets de un mismo incidente son diez veces más trabajo para el N2».
  - README, nivel 2       «Correlación: agrupar alertas del mismo ataque».

No es la correlación de nivel 1 (correlation.py), que junta el MISMO evento repetido en minutos ANTES de la IA. Esto
corre DESPUÉS del triaje y junta alertas de reglas distintas, aunque pasen días entre ellas.

Criterio: dos alertas son del mismo incidente si comparten una PISTA dentro de su ventana:

  pista       qué es                                                       ventana (desde la anterior)
  indicador   IP externa, dominio, hash, remitente, message_id, sesión IA   SOC_INCIDENT_DAYS (30 días: todo el reto)
  compte      la misma cuenta (usuario)                                    SOC_INCIDENT_ACCOUNT_DAYS (14 días)
  equip       el mismo equipo o IP interna                                 SOC_INCIDENT_HOST_HOURS (48 h)

y se unen en cadena (si A comparte con B y B con C, las tres son el mismo incidente). No sirven para juntar la gravedad,
la criticidad ni el tipo de regla: son filtros, no pruebas de que sea el mismo ataque.

Qué alertas entran: las que son ataque real, falta información o se escalan. Las autorizadas y las falsas alarmas no
forman incidentes (el pentest no es un ataque). Pistas que NO unen: dominios propios y servicios legítimos (Microsoft,
Google, CDN, uso dual), el proveedor legítimo de un correo, y equipos o cuentas «demasiado populares» (salen en más de
SOC_INCIDENT_HUB alertas: un servidor de salto o un controlador de dominio no prueban que dos ataques sean el mismo).

Decisión del incidente (política §5 y §6): se escala si alguna de sus alertas se escala o si es una CADENA (dos o más
reglas distintas con conclusión de ataque). La gravedad es la más alta de sus alertas (la matriz §2 se aplica alerta a
alerta; no inventamos un ajuste nuevo).
"""
from __future__ import annotations

import ipaddress
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
ATTACKISH = ("true_positive", "needs_more_info")

# Lo que no prueba que dos alertas sean del mismo ataque (lo usa medio mundo).
BENIGN_DOMAINS = ("microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "windows.net",
                  "windowsupdate.com", "google.com", "googleapis.com", "gstatic.com", "amazonaws.com", "cloudfront.net",
                  "akamaized.net", "azureedge.net", "apple.com", "github.com", "docusign.net", "npmjs.org",
                  "mega.nz", "mega.io", "anydesk.com", "teamviewer.com", "dropbox.com", "wetransfer.com")
FILE_EXT = {"exe", "dll", "json", "xlsx", "xls", "ps1", "zip", "pdf", "docx", "docm", "doc", "js", "txt", "csv", "tgz",
            "bat", "vbs", "lnk", "iso", "html", "htm", "png", "jpg", "msi", "sys", "log", "tmp", "dat", "py", "sh",
            "xml", "yml", "yaml", "cfg", "ini", "db", "bak", "rar", "7z", "gz", "tar", "eml", "msg", "one", "hta"}
# Terminaciones de dominio reales: sin esto, «adm.aortega» o «install.mjs» parecerían dominios.
TLDS = {"example", "com", "net", "org", "io", "nz", "sk", "ru", "cn", "info", "biz", "xyz", "top", "es", "cat", "eu",
        "de", "fr", "it", "nl", "uk", "co", "me", "app", "dev", "cloud", "online", "site", "live", "pw", "cc", "tk",
        "su", "ua", "us", "ca", "br", "in", "jp", "kr", "onion", "link", "club", "shop", "store", "tech", "ai",
        "ws", "to", "ly", "gg", "sh", "lt", "pl", "ro", "ir", "kp", "vn", "tr", "pt", "ch", "at", "be", "se", "no"}
INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+([a-z]{2,10}))\b", re.I)
SHA_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
MSGID_RE = re.compile(r"<[^<>\s]+@[^<>\s]+>")

LABEL = {"ip": "IP", "domini": "domini", "hash": "fitxer (hash)", "remitent": "remitent", "missatge": "correu",
         "sessio_ia": "sessió de l'assistent", "compte": "compte", "equip": "equip", "clau_cloud": "clau cloud"}
CLASS = {"ip": "indicador", "domini": "indicador", "hash": "indicador", "remitent": "indicador",
         "missatge": "indicador", "sessio_ia": "indicador", "clau_cloud": "indicador", "compte": "compte",
         "equip": "equip"}


def _env_float(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def windows_hours() -> dict[str, float]:
    return {"indicador": _env_float("SOC_INCIDENT_DAYS", 30) * 24,
            "compte": _env_float("SOC_INCIDENT_ACCOUNT_DAYS", 14) * 24,
            "equip": _env_float("SOC_INCIDENT_HOST_HOURS", 48)}


def hub_limit() -> int:
    return int(_env_float("SOC_INCIDENT_HUB", 25))


def _own_domains() -> tuple[str, ...]:
    raw = os.getenv("SOC_PROTECTED_DOMAINS", "tarvia.example")
    return tuple(d.strip().lower().lstrip(".") for d in raw.split(",") if d.strip())


def _under(domain: str, suffixes) -> bool:
    return any(domain == s or domain.endswith("." + s) for s in suffixes)


def _ts(alert: dict) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(alert.get("created_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _account(value: str) -> str | None:
    """«TARVIA\\adm.aortega», «adm.aortega@tarvia.example» y «adm.aortega» son la misma cuenta."""
    v = str(value).strip().lower().split("\\")[-1].split("@")[0]
    return v if re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,}", v) else None


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


# ----------------------------------------------------------------------------- pistas de una alerta

def pivots(alert: dict) -> set[tuple[str, str]]:
    """Pistas (tipo, valor) de una alerta, ya filtradas: nada propio de la empresa ni servicios legítimos."""
    ent, ev = alert.get("entities") or {}, alert.get("evidence") or {}
    own = _own_domains()
    legit = tuple(str(v).lower() for k, v in ev.items() if str(k).startswith("legit") and isinstance(v, str))
    out: set[tuple[str, str]] = set()

    def add_ip(raw: str) -> None:
        first = str(raw).split("-")[0].strip()
        try:
            ip = ipaddress.ip_address(first)
        except ValueError:
            return
        internal = any(ip in n for n in INTERNAL_NETS)
        out.add(("equip" if internal else "ip", str(ip)))

    def add_domain(raw: str) -> None:
        d = str(raw).strip().lower().strip(".")
        tld = d.rsplit(".", 1)[-1]
        if "." not in d or tld not in TLDS or tld in FILE_EXT or _under(d, own) or _under(d, BENIGN_DOMAINS) \
                or _under(d, legit):
            return
        out.add(("domini", d))

    for h in ent.get("hosts") or []:
        name = (h.get("hostname") or h.get("ip")) if isinstance(h, dict) else h
        if name and not IP_RE.fullmatch(str(name)):
            out.add(("equip", str(name).lower()))
        ip = h.get("ip") if isinstance(h, dict) else None
        if ip:
            add_ip(ip)
    for u in ent.get("users") or []:
        upn = u.get("upn") if isinstance(u, dict) else u
        if upn and (acc := _account(upn)) and "@" in str(upn):  # «(161 cuentas)» no identifica a nadie
            out.add(("compte", acc))
    for ip in ent.get("ips") or []:
        add_ip(ip)
    for d in ent.get("domains") or []:
        add_domain(d)
    for f in ent.get("files") or []:
        if isinstance(f, dict) and f.get("sha256"):
            out.add(("hash", str(f["sha256"]).lower()))
    if ent.get("ai_session"):
        out.add(("sessio_ia", str(ent["ai_session"])))
    cloud = ent.get("cloud")
    if isinstance(cloud, dict):
        for k in ("access_key_id", "accessKeyId", "access_key"):
            if cloud.get(k):
                out.add(("clau_cloud", str(cloud[k])))

    # La evidencia: aquí suelen estar el remitente, el dominio al que se llama, la cuenta usada… (texto libre)
    for k in ("account", "by", "user", "member_added"):
        if isinstance(ev.get(k), str) and (acc := _account(ev[k].split(" ")[0])) and acc not in ("system",):
            out.add(("compte", acc))
    if isinstance(ev.get("sender"), str) and "@" in ev["sender"]:
        out.add(("remitent", ev["sender"].strip().lower()))
    for text in _strings({k: v for k, v in ev.items() if not str(k).startswith("legit")}):
        for m in MSGID_RE.findall(text):
            out.add(("missatge", m.lower()))
        for m in SHA_RE.findall(text):
            out.add(("hash", m.lower()))
        for m in IP_RE.findall(text):
            add_ip(m)
        for m in EMAIL_RE.finditer(text):
            add_domain(m.group(1))
        for m in DOMAIN_RE.finditer(re.sub(r"[\w.+-]+@", " ", text)):
            add_domain(m.group(1))
    return out


# ----------------------------------------------------------------------------- agrupación

def _admitted(row: dict) -> bool:
    return row.get("verdict") in ATTACKISH or row.get("decision") == "escalate"


def _alert(row: dict) -> dict:
    return row.get("alert") or row


def _member_ids(row: dict) -> list[str]:
    alert = _alert(row)
    return list((alert.get("group") or row.get("group") or {}).get("alert_ids") or [alert["alert_id"]])


def _incident_id(first: dict) -> str:
    return "INC-" + str(_alert(first)["alert_id"]).removeprefix("ALR-")


def build(rows: list[dict]) -> list[dict]:
    """Incidentes (2 o más alertas) a partir de los resultados del triaje (vistas del front o TriagePreview)."""
    idx = [i for i, r in enumerate(rows) if _admitted(r) and _ts(_alert(r)) is not None]
    piv = {i: pivots(_alert(rows[i])) for i in idx}

    # Pistas demasiado populares (en más de SOC_INCIDENT_HUB alertas): no unen. Un servidor de salto, un remitente de
    # newsletters o un escáner que dispara cientos de veces la misma regla no prueban que dos ataques sean el mismo,
    # y encadenarían media empresa en un solo «incidente».
    seen_in: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i in idx:
        for p in piv[i]:
            seen_in[p].append(i)
    hub = hub_limit()
    usable = {p: ii for p, ii in seen_in.items() if 2 <= len(ii) <= hub}

    parent = {i: i for i in idx}

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    links: dict[tuple[int, int], set[tuple[str, str]]] = defaultdict(set)
    win = windows_hours()
    for p, members in usable.items():
        members = sorted(members, key=lambda i: _ts(_alert(rows[i])))
        limit = win[CLASS[p[0]]]
        for a, b in zip(members, members[1:]):
            gap = (_ts(_alert(rows[b])) - _ts(_alert(rows[a]))).total_seconds() / 3600
            if gap <= limit:
                parent[find(a)] = find(b)
                links[(a, b)].add(p)

    comps: dict[int, list[int]] = defaultdict(list)
    for i in idx:
        comps[find(i)].append(i)
    comp_links: dict[int, set] = defaultdict(set)
    for (a, _), ps in links.items():
        comp_links[find(a)] |= ps

    incidents = []
    for root, members in comps.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda i: _ts(_alert(rows[i])))
        incidents.append(_summarize([rows[i] for i in members], comp_links[root]))
    incidents.sort(key=lambda inc: (-SEVERITY_ORDER.index(inc["severity"]), inc["first_seen"]))
    return incidents


def _summarize(members: list[dict], shared: set[tuple[str, str]]) -> dict:
    alerts = [_alert(r) for r in members]
    attack = [r for r in members if r.get("verdict") == "true_positive" or r.get("decision") == "escalate"]
    rules = list(dict.fromkeys(str(a.get("rule_id") or "") for a in alerts))
    attack_rules = {str(_alert(r).get("rule_id") or "") for r in attack}
    tactics = list(dict.fromkeys((a.get("mitre") or {}).get("tactic") for a in alerts if (a.get("mitre") or {}).get("tactic")))
    sev = [r.get("severity") for r in members if r.get("severity") in SEVERITY_ORDER]
    severity = max(sev, key=SEVERITY_ORDER.index) if sev else "medium"
    chain = len(attack_rules) >= 2
    escalated = [r for r in members if r.get("decision") == "escalate"]

    reasons = []
    if chain:
        reasons.append(f"cadena d'atac: {len(attack_rules)} regles diferents amb conclusió d'atac "
                       f"({len(tactics)} fases MITRE) — política del SOC §5")
    if escalated:
        reasons.append(f"{len(escalated)} de les {len(members)} alertes ja s'escalaven per si soles")
    decision = "escalate" if chain or escalated else "close"

    accounts = sorted({v for k, v in shared if k == "compte"})
    ip_name = {str(h["ip"]): str(h["hostname"]).upper() for a in alerts for h in ((a.get("entities") or {}).get("hosts") or [])
               if isinstance(h, dict) and h.get("ip") and h.get("hostname")}
    hosts = sorted({v.upper() if not IP_RE.fullmatch(v) else ip_name.get(v, v)  # el nombre del equipo, no su IP
                    for k, v in shared if k == "equip"})
    if any(not IP_RE.fullmatch(h) for h in hosts):
        hosts = [h for h in hosts if not IP_RE.fullmatch(h)]
    indicators = sorted({f"{LABEL[k]} {v[:12] + '…' if k == 'hash' else v}" for k, v in shared if CLASS[k] == "indicador"})
    people = {str((u.get("upn") if isinstance(u, dict) else u) or "").lower()
              for a in alerts for u in ((a.get("entities") or {}).get("users") or [])} - {""}
    customers = {str((c.get("customer_id") if isinstance(c, dict) else c) or "")
                 for a in alerts for c in ((a.get("entities") or {}).get("customers") or [])} - {""}
    victims = len(people) + len(customers)
    ids = [i for r in members for i in _member_ids(r)]

    if indicators and victims >= 3 and not hosts:
        title = f"Campanya: el mateix atacant contra {victims} {'clients' if customers and not people else 'persones'}"
    elif hosts or accounts:
        subject = ", ".join((hosts + accounts)[:3])
        title = f"{'Cadena d' + chr(39) + 'atac' if chain else 'Activitat repetida'} sobre {subject}"
    else:
        title = f"{'Cadena d' + chr(39) + 'atac' if chain else 'Activitat repetida'} des de {indicators[0] if indicators else 'un mateix origen'}"
    title += f" · {len(ids)} alertes"

    return {
        "incident_id": _incident_id(members[0]),
        "title": title,
        "alert_ids": ids,
        "views": [_alert(r)["alert_id"] for r in members],  # una por fila de la bandeja
        "count": len(ids),
        "first_seen": alerts[0].get("created_at"),
        "last_seen": alerts[-1].get("created_at"),
        "rules": rules,
        "tactics": tactics,
        "severity": severity,
        "verdict": "true_positive" if any(r.get("verdict") == "true_positive" for r in members) else "needs_more_info",
        "decision": decision,
        "chain": chain,
        "reasons": reasons,
        "shared": [{"kind": k, "label": LABEL[k], "value": v} for k, v in sorted(shared)],
    }


def apply(rows: list[dict]) -> list[dict]:
    """Pone `incident_id` e `incident` en cada fila y, si el incidente es una cadena que se escala, escala también las
    alertas que por sí solas se cerraban (política §5), con una nota que lo explica. Devuelve los incidentes."""
    incs = build(rows)
    by_view = {v: inc for inc in incs for v in inc["views"]}
    for r in rows:
        inc = by_view.get(_alert(r)["alert_id"])
        r["incident_id"] = inc["incident_id"] if inc else None
        r["incident"] = ({k: inc[k] for k in ("incident_id", "title", "count", "decision", "chain", "severity")}
                         if inc else None)
        if inc and inc["decision"] == "escalate" and r.get("decision") == "close":
            r["decision"] = "escalate"
            note = (f"S'escala perquè forma part de l'incident {inc['incident_id']} ({inc['count']} alertes): "
                    + "; ".join(inc["reasons"]) + ".")
            r["decision_notes"] = list(r.get("decision_notes") or []) + [note]
            r["escalated_by_incident"] = True
    return incs
