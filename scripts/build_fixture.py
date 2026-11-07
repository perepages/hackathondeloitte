"""Genera data/fixture.json para que el front trabaje sin depender del back ni de la API.

Cada elemento es la salida REAL del back (`triage.analyze_alert(...).model_dump()`) más un
diccionario `_ejemplo` con los campos que el back todavía no genera (veredicto, decisión,
acciones, inyección...). Esos valores salen de unas reglas deterministas de prueba
(scripts/nivel1_triage.py) y heurísticas simples: sirven para diseñar las pantallas, NO son
el criterio final. `core/data.py` los usa solo si el back no trae el campo.

Requiere la API simulada de Deloitte en http://127.0.0.1:8000.

    .venv\\Scripts\\python.exe scripts/build_fixture.py
    .venv\\Scripts\\python.exe scripts/build_fixture.py --limit 20
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import nivel1_triage as reglas  # noqa: E402  (reglas de ejemplo)
from triage import analyze_alert  # noqa: E402  (back real)

DEFAULT_SAMPLE = os.path.join(ROOT, "..", "DTT-UAB-The-Hack", "03_alertas", "alertas_muestra_desarrollo.jsonl")
OUT = os.path.join(ROOT, "data", "fixture.json")

# Solo texto dirigido a NUESTRO clasificador (no los prompts de clientes al asistente de compra,
# que son el objeto de la propia alerta UC-AI-001).
INJECTION = re.compile(
    r"(display\s*:\s*none|sistema automatizado|clasificaci[oó]n de seguridad|clasificar como|no escalar|"
    r"marcar como (false_positive|falso positivo))", re.I)


def injection_flags(alert: dict) -> list[dict]:
    flags = []
    for key, value in (alert.get("evidence") or {}).items():
        if isinstance(value, str) and INJECTION.search(value):
            m = INJECTION.search(value)
            start = max(0, m.start() - 40)
            flags.append({"field": f"evidence.{key}", "excerpt": value[start:start + 160]})
    return flags


def recommended_actions(alert: dict, verdict: str, escalate: bool) -> list[dict]:
    rule, ev, ent = alert.get("rule_id", ""), alert.get("evidence") or {}, alert.get("entities") or {}
    hosts = [h.get("hostname") for h in ent.get("hosts", []) if isinstance(h, dict)]
    users = [u.get("upn") for u in ent.get("users", []) if isinstance(u, dict)]
    acts = []
    if verdict == "true_positive" and rule.startswith("UC-EML") and ev.get("sender"):
        acts.append({"action": "purge_email", "target": ev.get("message_id", "?"), "requires_approval": False,
                     "justification": "Correo malicioso confirmado: retirarlo de todos los buzones."})
        acts.append({"action": "block_ioc", "target": ev["sender"].split("@")[-1], "requires_approval": False,
                     "justification": "Dominio del remitente con mala reputación."})
    if verdict == "true_positive" and rule.startswith("UC-IDP") and users:
        acts.append({"action": "revoke_sessions", "target": users[0], "requires_approval": True,
                     "justification": "Posible cuenta comprometida."})
        acts.append({"action": "reset_password", "target": users[0], "requires_approval": True,
                     "justification": "Forzar cambio de credenciales."})
    if verdict == "true_positive" and escalate and hosts and rule.startswith(("UC-EDR", "UC-NET")):
        acts.append({"action": "isolate_host", "target": hosts[0], "requires_approval": True,
                     "justification": "Ejecución o C2 confirmados en el puesto."})
    if not acts:
        acts.append({"action": "escalate" if escalate else "close", "target": "ticket", "requires_approval": False,
                     "justification": "Escalar a N2 para revisión." if escalate else "Sin impacto: cerrar con justificación."})
    return acts


def example_fields(alert: dict) -> dict:
    r = reglas.triage(alert, with_trace=True)
    escalate = r["decision"].startswith("ESCALAR")
    flags = injection_flags(alert)
    verdict, why = r["verdict"], r["justification"]
    if flags:  # el contenido intenta manipular al clasificador: nunca baja la sospecha
        verdict, escalate = "true_positive", True
        why = "El correo contiene texto oculto dirigido al sistema automático de clasificación. " + why
    return {
        "verdict": verdict,
        "confidence": r["confidence"],
        "justification": why,
        "decision": "escalate" if escalate else "close",
        "asset_criticality": r["asset_criticality"],
        "title": f"{alert.get('rule_name')}: {why.split('.')[0][:90]}",
        "summary": why,
        "recommended_actions": recommended_actions(alert, verdict, escalate),
        "injection_flags": flags,
        "incident_id": None,
        "_fuente": "reglas de ejemplo (scripts/nivel1_triage.py), no el back",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=DEFAULT_SAMPLE)
    ap.add_argument("--limit", type=int, default=150)
    args = ap.parse_args()

    with open(args.sample, encoding="utf-8") as f:
        ids = [json.loads(line)["alert_id"] for line in f if line.strip()][: args.limit]

    out, t0 = [], time.time()
    for i, alert_id in enumerate(ids, 1):
        preview = analyze_alert(alert_id).model_dump()
        preview["_ejemplo"] = example_fields(preview["alert"])
        out.append(preview)
        if i % 10 == 0:
            print(f"{i}/{len(ids)} ({time.time() - t0:.0f} s)", flush=True)

    # Incidente de ejemplo: alertas que comparten remitente fraudulento
    by_sender: dict[str, list] = {}
    for p in out:
        s = (p["alert"].get("evidence") or {}).get("sender")
        if s and p["_ejemplo"]["injection_flags"]:
            by_sender.setdefault(s, []).append(p)
    for n, group in enumerate([g for g in by_sender.values() if len(g) > 1], 1):
        for p in group:
            p["_ejemplo"]["incident_id"] = f"INC-EJ-{n:03d}"

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"{len(out)} alertas -> {OUT} ({os.path.getsize(OUT) // 1024} KB, {time.time() - t0:.0f} s)")


if __name__ == "__main__":
    main()
