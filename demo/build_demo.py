"""Genera demo/triaje_demo.html a partir de la salida de nivel1_triage.py --trace.

    python nivel1_triage.py --sample ../DTT-UAB-The-Hack/03_alertas/alertas_muestra_desarrollo.jsonl \
        --limit 150 --trace --out demo/triaje.json
    python demo/build_demo.py demo/triaje.json
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALERT_KEYS = ("alert_id", "created_at", "source_product", "rule_id", "rule_name", "severity",
              "description", "entities", "evidence", "mitre", "runbook")


def flag(v):
    return str(v).lower() == "true"


def summarize(call: str, status: int, res):
    if status == 404 or res is None:
        if call.startswith("GET /assets/"):
            return "no está en la CMDB (equipo externo o no gestionado)"
        if call.startswith("GET /users/"):
            return "no está en el directorio"
        return "sin resultado"
    if call.startswith("GET /assets/"):
        vulns = len(res.get("vulnerabilities") or [])
        return (f"{res['hostname']} · criticidad {res['criticality']} · zona {res['zone']} · "
                f"{res['business_service']}" + (f" · {vulns} vulnerabilidades" if vulns else ""))
    if call.startswith("GET /users/"):
        tags = [t for t, k in (("VIP", "vip"), ("privilegiado", "privileged")) if flag(res.get(k))]
        return f"{res['display_name']} · {res['title']} ({res['department']})" + (" · " + ", ".join(tags) if tags else "")
    if call.startswith("GET /intel/"):
        parts = []
        tip = res.get("tip")
        parts.append(f"TIP: {tip['reputation']} ({tip.get('tags')}, confianza {tip.get('confidence')})" if tip
                     else "TIP: sin datos (desconocido no es limpio)")
        geo = res.get("geo")
        if geo:
            fl = [n for n, k in (("Tor", "is_tor"), ("VPN comercial", "is_vpn_provider"), ("hosting", "is_hosting"))
                  if flag(geo.get(k))]
            parts.append(f"{geo.get('as_org')} ({geo.get('country')})" + (" · " + ", ".join(fl) if fl else ""))
        return " · ".join(parts)
    if call.startswith("GET /changes"):
        if not res:
            return "ningún cambio aprobado coincide"
        return f"{len(res)} cambio(s): " + "; ".join(f"{c['id']} {c['titulo']}" for c in res[:2])
    return "ok"


def compact(r: dict) -> dict:
    a = r["alert"]
    return {
        **{k: r[k] for k in ("alert_id", "verdict", "confidence", "severity", "severity_rationale",
                             "justification", "decision", "asset_criticality", "rule_logic")},
        "alert": {k: a.get(k) for k in ALERT_KEYS},
        "trace": [{"call": t["call"], "ok": t["status"] == 200,
                   "summary": summarize(t["call"], t["status"], t["result"])} for t in r["trace"]],
    }


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "triaje.json")
    with open(src, encoding="utf-8") as f:
        rows = [compact(r) for r in json.load(f)]
    rows.sort(key=lambda r: r["alert"]["created_at"])
    data = json.dumps(rows, ensure_ascii=False).replace("</", "<\\/")
    with open(os.path.join(HERE, "template.html"), encoding="utf-8") as f:
        html = f.read().replace("/*__DATA__*/[]", data)
    out = os.path.join(HERE, "triaje_demo.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{len(rows)} alertas -> {out} ({os.path.getsize(out) // 1024} KB)")


if __name__ == "__main__":
    main()
