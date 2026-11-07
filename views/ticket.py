"""Ficha de ticket para el N2, en el formato de Deloitte (01_contexto/ticket_salida.schema.json).

Dueño: PERSONA A. Punto de partida: build_ticket() ya genera el JSON y lo valida.
Pendiente:
  - TODO A: diseño de la ficha (no solo el JSON): título, resumen, afectados, evidencias,
    acciones recomendadas (marcando las que requieren aprobación), escalado y preguntas abiertas.
"""
import json
import os

import streamlit as st

from core import data, ui

SCHEMA = os.path.join(data.ROOT, "..", "DTT-UAB-The-Hack", "01_contexto", "ticket_salida.schema.json")


def build_ticket(r: dict) -> dict:
    """Contrato del front -> ticket de Deloitte."""
    ctx = r["contexts"]
    assets = [c["data"] for c in ctx if c["kind"] == "asset"]
    ticket = {
        "ticket_id": f"TKT-{r['alert_id']}",
        "alert_ids": [r["alert_id"]],
        "title": r["title"] or r["rule_name"],
        "verdict": r["verdict"],
        "confidence": float(r["confidence"] or 0.0),
        "severity": r["severity"],
        "severity_rationale": r["severity_rationale"],
        "affected": {
            "users": [c["key"] for c in ctx if c["kind"] == "user"],
            "hosts": [a.get("hostname") for a in assets],
            "business_services": sorted({a.get("business_service") for a in assets if a.get("business_service")}),
            "customers": [c.get("customer_id") for c in (r["alert"].get("entities") or {}).get("customers", [])],
        },
        "summary": r["summary"] or r["justification"] or r["severity_rationale"],
        "evidence": [{"source": e.get("_source", ""), "event_id": e.get("event_id", ""),
                      "finding": e.get("event_type") or e.get("action") or ""} for e in r["related_logs"]],
        "enrichment": [{"indicator": q["path"].rsplit("/", 1)[-1], "type": "intel", "source": "TIP + GeoIP",
                        "result": q["summary"]} for q in r["queries"] if q["path"].startswith("/intel/")],
        "mitre": [m] if (m := (r["alert"].get("mitre") or {}).get("technique_id")) else [],
        "recommended_actions": r["recommended_actions"],
        "executed_actions": [],
        "escalation": {"escalate": r["decision"] == "escalate", "to": "N2" if r["decision"] == "escalate" else "",
                       "reason": r["justification"] if r["decision"] == "escalate" else ""},
        "open_questions": r["open_questions"],
    }
    return ticket


st.title("Ticket para N2")
rows = data.load_results()
ids = [r["alert_id"] for r in rows]
current = st.session_state.get("selected_alert") or next(r["alert_id"] for r in rows if r["decision"] == "escalate")
alert_id = st.selectbox("Alerta", ids, index=ids.index(current), key="ticket_alert",
                        format_func=lambda i: f"{i} · {data.get_result(i)['rule_name']}")
r = data.get_result(alert_id)
ticket = build_ticket(r)

if r["example_fields"]:
    st.info("Contiene campos de ejemplo (aún no los genera el back): " + ", ".join(r["example_fields"]))

try:
    import jsonschema
    with open(SCHEMA, encoding="utf-8") as f:
        jsonschema.validate(ticket, json.load(f))
    st.success("El ticket cumple el esquema de Deloitte.")
except FileNotFoundError:
    st.caption("No encuentro el esquema de Deloitte en ../DTT-UAB-The-Hack; no se valida.")
except Exception as exc:  # jsonschema.ValidationError
    st.error(f"El ticket no cumple el esquema: {exc}")

st.download_button("Descargar JSON", json.dumps(ticket, ensure_ascii=False, indent=2),
                   file_name=f"{ticket['ticket_id']}.json", mime="application/json")
st.json(ticket)
