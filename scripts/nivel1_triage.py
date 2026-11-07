"""Nivel 1 · Triaje básico de alertas del SOC de Tarvia (iteración 1).

Lee alertas de la API simulada de Deloitte (mock_soc_api, por defecto http://localhost:8000),
las enriquece con CMDB, directorio, TIP/GeoIP y calendario de cambios, y aplica reglas
deterministas para decidir veredicto, severidad final (matriz de politica_soc.md §2) y
si se cierra o se escala.

Uso:
    python nivel1_triage.py                    # 5 alertas, imprime por terminal
    python nivel1_triage.py --limit 20 --offset 100 --out resultados.json

Solo usa la librería estándar.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "http://127.0.0.1:8000"  # 127.0.0.1 y no localhost: en Windows evita ~2 s de espera IPv6 por petición

# --------------------------------------------------------------------------- cliente API

TRACE: list[dict] = []  # consultas hechas a la API para la alerta en curso


def api_get(path: str, **params):
    """GET a la API simulada. Devuelve el JSON o None si es 404."""
    q = {k: v for k, v in params.items() if v not in (None, "")}
    qs = ("?" + urllib.parse.urlencode(q)) if q else ""
    url = f"{API}{path}{qs}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            TRACE.append({"call": "GET " + urllib.parse.unquote(path + qs), "status": 404, "result": None})
            return None
        raise
    TRACE.append({"call": "GET " + urllib.parse.unquote(path + qs), "status": 200, "result": data})
    return data


def quote(s: str) -> str:
    return urllib.parse.quote(s, safe="")


# --------------------------------------------------------------------------- severidad

SEV = ["informational", "low", "medium", "high", "critical"]
CRIT = {"Baja": 0, "Media": 1, "Alta": 2, "Crítica": 3}
# Filas: severidad de la regla; columnas: criticidad del activo (Baja, Media, Alta, Crítica)
MATRIX = {
    "informational": ["informational", "informational", "low", "low"],
    "low":           ["informational", "low", "low", "medium"],
    "medium":        ["low", "medium", "medium", "high"],
    "high":          ["medium", "high", "high", "critical"],
    "critical":      ["high", "critical", "critical", "critical"],
}


def final_severity(rule_sev: str, crit: str, bump: int, verdict: str) -> tuple[str, str]:
    """Aplica la matriz §2 y el ajuste (máx. ±1). Devuelve (severidad, explicación)."""
    if verdict in ("benign_true_positive", "false_positive"):
        return "informational", f"veredicto {verdict} → informational (política §2)"
    base = MATRIX.get(rule_sev, MATRIX["medium"])[CRIT.get(crit, 1)]
    adj = max(-1, min(1, bump))
    sev = SEV[max(0, min(4, SEV.index(base) + adj))]
    txt = f"regla {rule_sev} × activo {crit} = {base}"
    if adj:
        txt += f", ajuste {adj:+d} → {sev}"
    return sev, txt


# --------------------------------------------------------------------------- enriquecimiento

def enrich(alert: dict) -> dict:
    ent = alert.get("entities", {})
    ctx = {"assets": [], "users": [], "intel": {}, "notes": []}

    for h in ent.get("hosts", []):
        a = api_get(f"/assets/{quote(h.get('hostname') or h.get('ip', ''))}")
        if a:
            ctx["assets"].append(a)
        else:
            ctx["notes"].append(f"{h.get('hostname')} no está en la CMDB")

    for u in ent.get("users", []):
        d = api_get(f"/users/{quote(u['upn'])}")
        if d:
            ctx["users"].append(d)

    indicators = list(ent.get("ips", [])) + list(ent.get("domains", []))
    ev = alert.get("evidence", {})
    if ev.get("sender") and "@" in ev["sender"]:
        indicators.append(ev["sender"].split("@", 1)[1])
    for k in ("domain", "parent_domain"):
        if ev.get(k):
            indicators.append(ev[k])
    for ind in dict.fromkeys(indicators):  # sin duplicados, en orden
        ctx["intel"][ind] = api_get(f"/intel/{quote(ind)}")
    return ctx


def worst_criticality(ctx: dict) -> str:
    crits = [a["criticality"] for a in ctx["assets"] if a.get("criticality") in CRIT]
    return max(crits, key=CRIT.get) if crits else "Media"  # sin activo conocido: Media por defecto


def bad_intel(ctx: dict) -> list[str]:
    out = []
    for ind, r in ctx["intel"].items():
        tip = (r or {}).get("tip")
        if tip and tip.get("reputation") in ("malicious", "suspicious"):
            out.append(f"{ind} = {tip['reputation']} ({tip.get('tags')}, conf {tip.get('confidence')})")
    return out


def is_true(v) -> bool:
    return str(v).lower() == "true"


# --------------------------------------------------------------------------- reglas por caso de uso
# Cada regla devuelve (verdict, confianza, justificación, bump_severidad)

REPUTABLE_SUFFIXES = (
    "microsoft.com", "googleapis.com", "amazonaws.com", "windows.net", "akamaized.net",
    "azureedge.net", "cloudfront.net", "cdn77.example", "docusign.net", "linkedin.com",
)


def domain_reputable(d: str) -> bool:
    return any(d == s or d.endswith("." + s) for s in REPUTABLE_SUFFIXES)


def r_waf(a, ctx, bad):
    ev = a["evidence"]
    if ev.get("action") == "blocked":
        geo = next((r.get("geo") for r in ctx["intel"].values() if r and r.get("geo")), None) or {}
        src = geo.get("as_org", "origen externo")
        return ("true_positive", 0.8,
                f"Intento real de {ev.get('rule_msg')} ({ev.get('hits')} hits) desde {src}, "
                "pero el WAF lo bloqueó y no hay efecto: ruido de Internet, cerrar.", -1)
    return ("true_positive", 0.6, f"{ev.get('rule_msg')} NO bloqueado por el WAF: revisar respuesta de la app.", +1)


def r_phish_report(a, ctx, bad):
    ev = a["evidence"]
    sender = ev.get("sender", "")
    dom = sender.split("@", 1)[-1].lower()
    subj = ev.get("subject", "")
    legit = ev.get("legit_supplier_domain")
    if legit and legit.lower() != dom:
        return ("true_positive", 0.85,
                f"Posible fraude BEC: remitente {dom} suplanta al proveedor legítimo {legit}.", +1)
    if bad:
        return ("true_positive", 0.9, f"Phishing reportado; TIP: {'; '.join(bad)}. Purgar correo y bloquear dominio.", 0)
    if dom == "tarvia.example" and "simulacro" in subj.lower():
        return ("benign_true_positive", 0.9, "Correo del simulacro interno de phishing (RRHH): el usuario lo detectó bien.", 0)
    if re.search(r"[a-z]0[a-z]|[a-z]1[a-z]", dom) or re.search(r"(has ganado|premio|caducad|urgente)", subj.lower()):
        return ("true_positive", 0.7, f"Dominio/asunto con señales de engaño ({dom}: «{subj}»), sin datos en TIP.", 0)
    if domain_reputable(dom):
        return ("false_positive", 0.8, f"Remitente legítimo ({dom}), asunto «{subj}»: correo transaccional reportado por error.", 0)
    return ("false_positive", 0.6, f"Newsletter/comercial de {dom} sin indicadores maliciosos (TIP sin datos ≠ limpio).", 0)


def r_encoded_ps(a, ctx, bad):
    ev = a["evidence"]
    if "CcmExec" in ev.get("parent", "") and ev.get("user") == "SYSTEM":
        chg = api_get("/changes", q="SCCM") or []
        cite = chg[0]["id"] if chg else "sin cambio localizado"
        return ("benign_true_positive", 0.9,
                f"PowerShell codificado lanzado por el agente SCCM como SYSTEM (inventario de software). Cambio aprobado {cite}.", 0)
    return ("needs_more_info", 0.5, f"PowerShell codificado con padre {ev.get('parent')}: decodificar y revisar.", 0)


def r_impossible_travel(a, ctx, bad):
    ev = a["evidence"]
    geos = [r.get("geo") or {} for r in ctx["intel"].values() if r]
    anon = [g for g in geos if is_true(g.get("is_tor")) or is_true(g.get("is_vpn_provider"))]
    post = ev.get("post_login_actions")
    known_dev = "conocido" in str(ev.get("device", ""))
    if anon or post:
        why = []
        if anon:
            why.append("login desde " + ", ".join(g.get("as_org", "?") for g in anon))
        if post:
            why.append("acciones posteriores: " + ", ".join(post))
        return ("true_positive", 0.75, "Posible cuenta comprometida: " + "; ".join(why) + ".", +1)
    if known_dev:
        relay = [g.get("as_org") for g in geos if "Relay" in str(g.get("as_org"))]
        extra = f" La IP lejana es {relay[0]}." if relay else ""
        return ("false_positive", 0.8, f"Dispositivo corporativo conocido y conforme, sin anonimizadores ni acciones raras.{extra}", 0)
    return ("needs_more_info", 0.5, "Viaje imposible con dispositivo no reconocido: verificar con el usuario.", 0)


def r_beacon(a, ctx, bad):
    dom = a["evidence"].get("domain", "")
    if bad:
        return ("true_positive", 0.9, f"Beaconing a C2 conocido: {'; '.join(bad)}. Aislar puesto (con aprobación N2).", +1)
    if domain_reputable(dom) or dom.endswith("tarvia-printers.example") or "bmc-agent" in dom:
        return ("false_positive", 0.8, f"Beaconing a servicio legítimo/de gestión ({dom}): telemetría periódica esperada.", 0)
    return ("needs_more_info", 0.5, f"Beaconing a {dom} sin reputación en TIP (desconocido ≠ limpio).", 0)


def r_dga(a, ctx, bad):
    pd_ = a["evidence"].get("parent_domain", "")
    if bad:
        return ("true_positive", 0.85, f"Dominio de alta entropía con mala reputación: {'; '.join(bad)}.", 0)
    if domain_reputable(pd_):
        return ("false_positive", 0.85, f"Subdominio aleatorio de un CDN/cloud legítimo ({pd_}), patrón normal.", 0)
    return ("needs_more_info", 0.5, f"Dominio DGA bajo {pd_} sin reputación conocida.", 0)


def r_office_child(a, ctx, bad):
    ev = a["evidence"]
    tree = ev.get("process_tree", "")
    if ev.get("signer") and tree.endswith("saplogon.exe"):
        return ("benign_true_positive", 0.85, f"{tree} firmado por {ev['signer']}: integración Excel-SAP habitual.", 0)
    return ("true_positive", 0.7, f"Cadena de procesos sospechosa sin firma: {tree}. Posible ejecución maliciosa.", +1)


INJECTION_HINTS = re.compile(
    r"(system prompt|prompt de sistema|instrucciones|ignora (todas|tus)|modo (admin|desarrollador)|"
    r"descuento|otro cliente|pedidos de|api key|contraseña|<\s*script)", re.I)


def r_ai_injection(a, ctx, bad):
    ex = a["evidence"].get("prompt_excerpt", "")
    if INJECTION_HINTS.search(ex):
        return ("true_positive", 0.75, f"Intento de manipular el asistente: «{ex[:80]}».", 0)
    return ("false_positive", 0.8, f"Frase normal de cliente que el guardarraíl confundió con injection: «{ex[:80]}».", 0)


def r_av(a, ctx, bad):
    ev = a["evidence"]
    if not ev.get("executed") and ev.get("action") in ("quarantined", "blocked"):
        return ("true_positive", 0.85,
                f"Malware {ev.get('detection_name')} detectado y {ev['action']} por el AV sin ejecutarse.", -1)
    return ("true_positive", 0.8, f"Malware {ev.get('detection_name')} con ejecución o sin bloquear.", +1)


RULES = {
    "UC-WEB-001": r_waf,
    "UC-EML-001": r_phish_report,
    "UC-EDR-002": r_encoded_ps,
    "UC-IDP-001": r_impossible_travel,
    "UC-NET-001": r_beacon,
    "UC-NET-005": r_dga,
    "UC-EDR-001": r_office_child,
    "UC-AI-001": r_ai_injection,
    "UC-EDR-003": r_av,
}


def r_default(a, ctx, bad):
    if bad:
        return ("true_positive", 0.7, f"Indicadores con mala reputación: {'; '.join(bad)}.", 0)
    return ("needs_more_info", 0.4, f"Regla {a['rule_id']} sin lógica N1 automática todavía: revisión humana.", 0)


# --------------------------------------------------------------------------- triaje

def triage(alert: dict, with_trace: bool = False) -> dict:
    TRACE.clear()
    ctx = enrich(alert)
    bad = bad_intel(ctx)
    verdict, conf, why, bump = RULES.get(alert["rule_id"], r_default)(alert, ctx, bad)

    # +1 por identidad VIP o privilegiada (política §2)
    vip = [u["upn"] for u in ctx["users"] if is_true(u.get("vip")) or is_true(u.get("privileged"))]
    if vip and verdict in ("true_positive", "needs_more_info"):
        bump += 1
        why += f" Identidad VIP/privilegiada: {', '.join(vip)}."

    crit = worst_criticality(ctx)
    sev, sev_txt = final_severity(alert["severity"], crit, bump, verdict)

    escalate = (verdict == "true_positive" and sev in ("high", "critical")) or \
               (verdict == "needs_more_info" and sev in ("medium", "high", "critical"))
    out = {
        "alert_id": alert["alert_id"],
        "rule": f"{alert['rule_id']} {alert['rule_name']}",
        "verdict": verdict,
        "confidence": conf,
        "severity": sev,
        "severity_rationale": sev_txt,
        "justification": why + (" " + "; ".join(ctx["notes"]) if ctx["notes"] else ""),
        "decision": "ESCALAR a N2" if escalate else "CERRAR",
    }
    if with_trace:
        out["alert"] = alert
        out["asset_criticality"] = crit
        out["rule_logic"] = RULES.get(alert["rule_id"], r_default).__name__
        out["trace"] = [dict(t) for t in TRACE]
    return out


def main():
    global API
    ap = argparse.ArgumentParser(description="Triaje N1 determinista contra la API simulada de Deloitte")
    ap.add_argument("--api", default=API)
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--out", help="guardar resultados en este JSON")
    ap.add_argument("--sample", help="JSONL con alert_id a triar (p. ej. alertas_muestra_desarrollo.jsonl)")
    ap.add_argument("--trace", action="store_true", help="incluir en --out la alerta y las consultas hechas")
    args = ap.parse_args()
    API = args.api.rstrip("/")

    try:
        if args.sample:
            with open(args.sample, encoding="utf-8") as f:
                ids = [json.loads(l)["alert_id"] for l in f if l.strip()]
            ids = ids[args.offset:args.offset + args.limit]
            items = [a for a in (api_get(f"/alerts/{quote(i)}") for i in ids) if a]
            page = {"total": len(ids), "items": items}
        else:
            page = api_get("/alerts", status="new", limit=args.limit, offset=args.offset)
    except urllib.error.URLError as e:
        sys.exit(f"No se puede conectar con la API en {API}: {e}. ¿Está arrancado mock_soc_api?")

    results = [triage(a, with_trace=args.trace) for a in page["items"]]
    for r in results:
        print(f"\n[{r['alert_id']}] {r['rule']}")
        print(f"  Veredicto : {r['verdict']} (conf {r['confidence']})")
        print(f"  Severidad : {r['severity']}  ({r['severity_rationale']})")
        print(f"  Decisión  : {r['decision']}")
        print(f"  Motivo    : {r['justification']}")
    print(f"\n{len(results)} alertas triadas (de {page['total']} en cola).")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"Guardado en {args.out}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main()
