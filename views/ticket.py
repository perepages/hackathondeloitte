"""Ficha de ticket para el N2, en el formato de Deloitte (01_contexto/ticket_salida.schema.json).

Dueño: PERSONA A. Arriba la ficha legible; abajo el JSON validado y descargable.
"""
import json
import os

import pandas as pd
import streamlit as st

from core import data, ui

SCHEMA = os.path.join(data.ROOT, "..", "DTT-UAB-The-Hack", "01_contexto", "ticket_salida.schema.json")


def build_ticket(r: dict) -> dict:
    """Contrato del front -> ticket de Deloitte. La decisión de la persona, si existe, manda sobre la propuesta."""
    ctx = r["contexts"]
    assets = [c["data"] for c in ctx if c["kind"] == "asset"]
    decision = (r.get("review") or {}).get("decision") or r["decision"]
    return {
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
        "escalation": {"escalate": decision == "escalate", "to": "N2" if decision == "escalate" else "",
                       "reason": r["justification"] if decision == "escalate" else ""},
        "open_questions": r["open_questions"],
    }


def validate(ticket: dict) -> str | None:
    """None si cumple el esquema; el error si no; 'sin-esquema' si no está el dataset al lado."""
    try:
        import jsonschema
        with open(SCHEMA, encoding="utf-8") as f:
            jsonschema.validate(ticket, json.load(f))
        return None
    except FileNotFoundError:
        return "sin-esquema"
    except Exception as exc:  # jsonschema.ValidationError
        return str(exc).splitlines()[0]


rows = data.load_results()
ids = [r["alert_id"] for r in rows]
current = st.session_state.get("selected_alert") or next(r["alert_id"] for r in rows if r["decision"] == "escalate")
st.title("Ticket para N2")
alert_id = st.selectbox("Alerta", ids, index=ids.index(current), key="ticket_alert",
                        format_func=lambda i: f"{i} · {data.get_result(i)['rule_name']}")
st.session_state["selected_alert"] = alert_id
r = data.get_result(alert_id)
t = build_ticket(r)
rv = r["review"]

# ---------------------------------------------------------------------------- cabecera
with st.container(border=True):
    st.markdown(f"{ui.severity_badge(t['severity'])} &nbsp; {ui.verdict_badge(t['verdict'])} &nbsp; "
                f"`{t['ticket_id']}`", unsafe_allow_html=True)
    st.subheader(t["title"], anchor=False)
    esc = t["escalation"]["escalate"]
    who = (f"decidido por **{rv['analyst']}**" if rv else "propuesta del sistema, **sin revisar por una persona**")
    (st.warning if esc else st.info)(("**Escalar a N2** · " if esc else "**Cerrar** · ") + who)
    st.markdown(f"**Resumen.** {ui.md(t['summary'])}")
    m = st.columns(3)
    m[0].metric("Confianza", f"{round(t['confidence'] * 100)} %" if r["confidence"] is not None else "—")
    m[1].metric("Severidad", ui.SEVERITY_LABEL[t["severity"]])
    m[2].metric("MITRE", ", ".join(t["mitre"]) or "—")
    st.caption(t["severity_rationale"])
    if r["example_fields"]:
        st.caption("Contiene campos de ejemplo (aún no los genera el back): " + ", ".join(r["example_fields"]))

# ---------------------------------------------------------------------------- cuerpo
c1, c2 = st.columns(2, gap="large")
with c1:
    st.markdown("**Afectados**")
    aff = t["affected"]
    st.dataframe(pd.DataFrame([("Usuarios", ", ".join(aff["users"]) or "—"), ("Equipos", ", ".join(aff["hosts"]) or "—"),
                               ("Servicios de negocio", ", ".join(aff["business_services"]) or "—"),
                               ("Clientes", ", ".join(aff["customers"]) or "—")], columns=["", "Valor"]),
                 hide_index=True, use_container_width=True)
    st.markdown("**Enriquecimiento**")
    if t["enrichment"]:
        st.dataframe(pd.DataFrame(t["enrichment"])[["indicator", "result"]].rename(
            columns={"indicator": "Indicador", "result": "Resultado"}), hide_index=True, use_container_width=True)
    else:
        st.caption("Sin indicadores consultados.")
with c2:
    st.markdown("**Acciones recomendadas**")
    acts = [{"Acción": ui.ACTION_LABEL.get(x["action"], x["action"]), "Objetivo": x["target"],
             "Aprobación": "N2" if x["requires_approval"] else "no hace falta", "Motivo": x.get("justification", "")}
            for x in t["recommended_actions"]]
    if acts:
        st.dataframe(pd.DataFrame(acts), hide_index=True, use_container_width=True)
    if any(x["requires_approval"] for x in t["recommended_actions"]):
        if st.button("Ir a contención", key="ticket_to_contencion"):
            st.switch_page("views/contencion.py")
    st.markdown("**Evidencias**")
    if t["evidence"]:
        st.dataframe(pd.DataFrame(t["evidence"]).rename(columns={"source": "Fuente", "event_id": "Evento",
                                                                 "finding": "Hallazgo"}),
                     hide_index=True, use_container_width=True)
    else:
        st.caption("Sin eventos relacionados en los logs.")

if t["open_questions"]:
    with st.container(border=True):
        st.markdown("**Preguntas abiertas para el N2**")
        for oq in t["open_questions"]:
            st.markdown(f"- {ui.md(oq)}")

# ---------------------------------------------------------------------------- JSON
err = validate(t)
v1, v2 = st.columns([3, 1])
if err is None:
    v1.success("El ticket cumple el esquema de Deloitte (ticket_salida.schema.json).")
elif err == "sin-esquema":
    v1.caption("No encuentro el esquema en ../DTT-UAB-The-Hack; no se ha validado.")
else:
    v1.error(f"El ticket no cumple el esquema: {err}")
v2.download_button("Descargar JSON", json.dumps(t, ensure_ascii=False, indent=2), file_name=f"{t['ticket_id']}.json",
                   mime="application/json", use_container_width=True, key="ticket_download")
with st.expander("Ver JSON"):
    st.json(t)
