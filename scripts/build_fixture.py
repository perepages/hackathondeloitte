"""Genera data/fixture.json para que el front trabaje sin depender del back ni de la API.

Cada elemento es la salida REAL del back (`triage.analyze_alert(...).model_dump()`) más un
diccionario `_ejemplo` con los campos que el back todavía no genera (veredicto, decisión,
acciones, inyección...). Esos valores salen de unas reglas deterministas de prueba
(scripts/nivel1_triage.py) y heurísticas simples: sirven para diseñar las pantallas, NO son
el criterio final. `core/data.py` los usa solo si el back no trae el campo.

Requiere la API simulada de Deloitte en http://127.0.0.1:8000.

    .venv\\Scripts\\python.exe scripts/build_fixture.py
    .venv\\Scripts\\python.exe scripts/build_fixture.py --limit 20

Probar otro LLM sin pisar la muestra (p. ej. Ollama) y compararlo con la de referencia:
    $env:LLM_PROVIDER="ollama"; $env:LLM_MODEL="llama3"
    .venv\\Scripts\\python.exe scripts/build_fixture.py --out data/fixture_llama3.json --workers 1 --reference data/fixture.json
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
import soc_api  # noqa: E402
from triage import analyze_alert  # noqa: E402  (back real)

reglas.API = soc_api.BASE_URL  # la misma API que el back (SOC_API_URL), no la dirección fija de las reglas
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
    ap.add_argument("--out", default=OUT, help="dónde guardar la muestra (por defecto data/fixture.json)")
    ap.add_argument("--reference", help="otra muestra con la que comparar veredictos (p. ej. data/fixture.json)")
    args = ap.parse_args()
    out_path = os.path.abspath(args.out)
    comparison_path = os.path.splitext(out_path)[0] + "_comparacion.json" if out_path != OUT else COMPARISON
    import assistant
    print(f"LLM: {assistant.config()['provider']} · modelo {assistant.config()['model']} · "
          f"{assistant.available()[1]} · motor {os.getenv('SOC_VERDICT_ENGINE', 'auto')}", flush=True)

    with open(args.sample, encoding="utf-8") as f:
        ids = [json.loads(line)["alert_id"] for line in f if line.strip()][: args.limit]

    import correlation
    # Correlación de nivel 1 antes de triar (igual que en directo): el mismo evento repetido en la ventana se
    # tría una sola vez, como una alerta agrupada
    alerts = correlation.correlate([soc_api.get_alert(i) for i in ids])
    n_grouped = sum(1 for a in alerts if a.get("group"))
    print(f"{len(ids)} alertes -> {len(alerts)} després d'agrupar ({n_grouped} grups, finestra "
          f"{correlation.window_minutes():g} min)", flush=True)

    def one(alert: dict) -> dict:
        preview = analyze_alert(alert["alert_id"], alert=alert).model_dump()
        preview["_ejemplo"] = example_fields(preview["alert"])
        return preview

    from concurrent.futures import ThreadPoolExecutor
    out, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for i, preview in enumerate(pool.map(one, alerts), 1):
            out.append(preview)
            if i % 10 == 0:
                print(f"{i}/{len(alerts)} ({time.time() - t0:.0f} s)", flush=True)

    # Incidente de ejemplo: alertas que comparten remitente fraudulento
    by_sender: dict[str, list] = {}
    for p in out:
        s = (p["alert"].get("evidence") or {}).get("sender")
        if s and p["_ejemplo"]["injection_flags"]:
            by_sender.setdefault(s, []).append(p)
    for n, group in enumerate([g for g in by_sender.values() if len(g) > 1], 1):
        for p in group:
            p["_ejemplo"]["incident_id"] = f"INC-EJ-{n:03d}"

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"{len(out)} alertas -> {out_path} ({os.path.getsize(out_path) // 1024} KB, {time.time() - t0:.0f} s, "
          f"{(time.time() - t0) / max(1, len(out)):.1f} s por alerta con {args.workers} en paralelo)")
    reference = None
    if args.reference:
        with open(args.reference, encoding="utf-8") as f:
            reference = {p["alert"]["alert_id"]: p for p in json.load(f)}
    compare(out, comparison_path, reference)


def compare(out: list[dict], path: str = COMPARISON, reference: dict | None = None) -> None:
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
    failures = Counter(n.split("(", 1)[-1].split(")")[0][:80] for p in out for n in p.get("decision_notes") or []
                       if n.startswith("La IA no dio una propuesta válida"))
    if failures:
        report["fallos_llm"] = dict(failures.most_common())
    if reference:
        both = [p for p in out if p["alert"]["alert_id"] in reference]
        ref = lambda p: reference[p["alert"]["alert_id"]]  # noqa: E731
        report["frente_a_referencia"] = {
            "comparadas": len(both),
            "mismo_veredicto": sum(p["verdict"] == ref(p)["verdict"] for p in both),
            "misma_decision": sum(p["decision"] == ref(p)["decision"] for p in both),
            "discrepancias": [{"alert_id": p["alert"]["alert_id"], "rule_id": p["alert"].get("rule_id"),
                               "este": [p["verdict"], p["decision"]], "referencia": [ref(p)["verdict"], ref(p)["decision"]],
                               "justificacion": p["justification"][:300]}
                              for p in both if (p["verdict"], p["decision"]) != (ref(p)["verdict"], ref(p)["decision"])],
        }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    n = len(out) or 1
    print(f"Origen de la propuesta: {dict(sources)}")
    print(f"Mismo veredicto que las reglas: {same_verdict}/{len(out)} ({same_verdict / n:.0%}); "
          f"misma decisión: {same_decision}/{len(out)} ({same_decision / n:.0%})")
    if failures:
        print(f"Fallos del LLM (se usaron las reglas): {dict(failures.most_common(5))}")
    if reference:
        r = report["frente_a_referencia"]
        print(f"Frente a la referencia: mismo veredicto {r['mismo_veredicto']}/{r['comparadas']}, "
              f"misma decisión {r['misma_decision']}/{r['comparadas']}")
    print(f"Discrepancias -> {path}")


if __name__ == "__main__":
    main()
