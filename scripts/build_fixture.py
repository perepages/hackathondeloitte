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
from verdict import NO_APPROVAL, default_actions, injection_flags  # noqa: E402

DEFAULT_SAMPLE = os.path.join(ROOT, "..", "DTT-UAB-The-Hack", "03_alertas", "alertas_muestra_desarrollo.jsonl")
OUT = os.path.join(ROOT, "data", "fixture.json")
COMPARISON = os.path.join(ROOT, "data", "comparacion_veredictos.json")


def recommended_actions(alert: dict, verdict: str, escalate: bool) -> list[dict]:
    acts = [{**a, "requires_approval": a["action"] not in NO_APPROVAL}
            for a in default_actions(alert, verdict, escalate)]
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
    ap.add_argument("--workers", type=int, default=4, help="alertas en paralelo (cada una llama a la API y al LLM)")
    args = ap.parse_args()

    with open(args.sample, encoding="utf-8") as f:
        ids = [json.loads(line)["alert_id"] for line in f if line.strip()][: args.limit]

    def one(alert_id: str) -> dict:
        preview = analyze_alert(alert_id).model_dump()
        preview["_ejemplo"] = example_fields(preview["alert"])
        return preview

    from concurrent.futures import ThreadPoolExecutor
    out, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for i, preview in enumerate(pool.map(one, ids), 1):
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
    compare(out)


def compare(out: list[dict]) -> None:
    """Back (LLM + política) frente a las reglas de ejemplo: dónde coinciden y dónde no."""
    from collections import Counter
    sources = Counter(p.get("decision_source") for p in out)
    same_verdict = sum(p["verdict"] == p["_ejemplo"]["verdict"] for p in out)
    same_decision = sum(p["decision"] == p["_ejemplo"]["decision"] for p in out)
    diffs = [{
        "alert_id": p["alert"]["alert_id"], "rule_id": p["alert"].get("rule_id"),
        "back": {k: p[k] for k in ("verdict", "decision", "severity", "confidence", "justification")},
        "reglas": {k: p["_ejemplo"][k] for k in ("verdict", "decision", "justification")},
        "notas": p.get("decision_notes"),
    } for p in out if p["verdict"] != p["_ejemplo"]["verdict"] or p["decision"] != p["_ejemplo"]["decision"]]
    report = {
        "total": len(out), "origen_propuesta": dict(sources),
        "mismo_veredicto": same_verdict, "misma_decision": same_decision,
        "veredictos_back": dict(Counter(p["verdict"] for p in out)),
        "decisiones_back": dict(Counter(p["decision"] for p in out)),
        "discrepancias_por_regla": dict(Counter(d["rule_id"] for d in diffs).most_common()),
        "discrepancias": diffs,
    }
    with open(COMPARISON, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    n = len(out) or 1
    print(f"Origen de la propuesta: {dict(sources)}")
    print(f"Mismo veredicto que las reglas: {same_verdict}/{len(out)} ({same_verdict / n:.0%}); "
          f"misma decisión: {same_decision}/{len(out)} ({same_decision / n:.0%})")
    print(f"Discrepancias -> {COMPARISON}")


if __name__ == "__main__":
    main()
