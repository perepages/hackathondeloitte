"""Informe para N2: el ticket en el formato de Deloitte (01_contexto/ticket_salida.schema.json).

Dueño: PERSONA A. Arriba el informe legible para una persona; abajo el JSON validado y descargable.
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
    title = r["title"] if r["title"] and "title" not in r["example_fields"] else \
        f"{r['rule_name']}: {ui.VERDICT_LABEL[r['verdict']].lower()}"
    return {
        "ticket_id": f"TKT-{r['alert_id']}",
        "alert_ids": [r["alert_id"]],
        "title": title,
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
ids = [r["alert_id"] for r in ui.by_severity(rows)]  # en el desplegable, de más a menos grave
if not rows:
    st.title("Informe para N2")
    ui.empty_state("informes")
current = st.session_state.get("selected_alert")
if current not in ids:
    current = next((r["alert_id"] for r in rows if r["decision"] == "escalate"), ids[0])

st.title("Informe para N2")
st.markdown('<p class="muted">Lo que recibe el analista senior cuando una alerta se escala: qué ha pasado, a quién '
            "afecta, en qué se basa la conclusión y qué se recomienda hacer. Sigue el formato oficial de Deloitte.</p>",
            unsafe_allow_html=True)
alert_id = st.selectbox("Alerta", ids, index=ids.index(current), key="ticket_alert",
                        format_func=lambda i: ui.option_label(data.get_result(i)),
                        help="🔴 crítica · 🟠 alta · 🟡 media · 🔵 baja · ⚪ informativa")
st.session_state["selected_alert"] = alert_id
r = data.get_result(alert_id)
t = build_ticket(r)
rv = r["review"]

# ---------------------------------------------------------------------------- cabecera
with st.container(border=True):
    st.markdown(f"{ui.severity_badge(t['severity'])} &nbsp; {ui.verdict_badge(t['verdict'])}"
                f"{ui.example_tag(r, 'verdict')} &nbsp; <span class='muted'>{ui.esc(t['ticket_id'])}</span>",
                unsafe_allow_html=True)
    st.subheader(t["title"], anchor=False)
    esc = t["escalation"]["escalate"]
    who = (f"decidido por {rv['analyst']}" if rv else "propuesta del sistema, todavía sin revisar por una persona")
    (st.warning if esc else st.info)(("**Se escala a N2** · " if esc else "**Se cierra** · ") + who)
    st.markdown(f"**Qué ha pasado.** {ui.md(t['summary'])}")
    m = st.columns(3)
    m[0].metric("Seguridad de la conclusión", f"{round(t['confidence'] * 100)} %" if r["confidence"] is not None else "—")
    m[1].metric("Gravedad", ui.SEVERITY_LABEL[t["severity"]].capitalize(), help=ui.SEVERITY_HELP[t["severity"]])
    m[2].metric("Técnica de ataque (MITRE)", ", ".join(t["mitre"]) or "—")

# ---------------------------------------------------------------------------- cuerpo
c1, c2 = st.columns(2, gap="large")
with c1:
    st.markdown("**A quién afecta**")
    aff = t["affected"]
    st.dataframe(pd.DataFrame([("Personas", ", ".join(aff["users"]) or "—"), ("Equipos", ", ".join(aff["hosts"]) or "—"),
                               ("Servicios de negocio", ", ".join(aff["business_services"]) or "—"),
                               ("Clientes", ", ".join(aff["customers"]) or "—")], columns=["Qué", "Cuál"]),
                 hide_index=True, use_container_width=True)
    st.markdown("**Qué se sabe de los indicadores**")
    if t["enrichment"]:
        st.dataframe(pd.DataFrame(t["enrichment"])[["indicator", "result"]].rename(
            columns={"indicator": "Indicador", "result": "Resultado"}), hide_index=True, use_container_width=True)
    else:
        st.caption("No había IPs ni dominios que consultar.")
with c2:
    st.markdown(f"**Qué recomienda hacer** {ui.example_tag(r, 'recommended_actions')}", unsafe_allow_html=True)
    acts = [{"Acción": ui.ACTION_LABEL.get(x["action"], x["action"]), "Sobre": x["target"],
             "¿Necesita aprobación?": "Sí, de N2" if x["requires_approval"] else "No"}
            for x in t["recommended_actions"]]
    if acts:
        st.dataframe(pd.DataFrame(acts), hide_index=True, use_container_width=True)
    if any(x["requires_approval"] for x in t["recommended_actions"]):
        if st.button("Ir a aprobar estas acciones", key="ticket_to_contencion", icon=":material/shield:"):
            st.switch_page("views/contencion.py")
    st.markdown("**Registros que lo respaldan**")
    if t["evidence"]:
        st.dataframe(pd.DataFrame(t["evidence"]).rename(columns={"source": "Fuente", "event_id": "Registro",
                                                                 "finding": "Qué muestra"}),
                     hide_index=True, use_container_width=True)
    else:
        st.caption("No se encontraron registros relacionados.")

if t["open_questions"]:
    with st.container(border=True):
        st.markdown("**Lo que queda por comprobar**")
        for oq in t["open_questions"]:
            st.markdown(f"- {ui.md(oq)}")

# ---------------------------------------------------------------------------- JSON
st.divider()
err = validate(t)
v1, v2 = st.columns([3, 1], vertical_alignment="center")
if err is None:
    v1.success("Formato comprobado: el informe cumple el esquema oficial de Deloitte (ticket_salida.schema.json).",
               icon=":material/verified:")
elif err == "sin-esquema":
    v1.caption("No encuentro el esquema de Deloitte en ../DTT-UAB-The-Hack; no se ha comprobado el formato.")
else:
    v1.error(f"El informe no cumple el esquema: {err}")
v2.download_button("Descargar informe (JSON)", json.dumps(t, ensure_ascii=False, indent=2),
                   file_name=f"{t['ticket_id']}.json", mime="application/json", use_container_width=True,
                   key="ticket_download", icon=":material/download:")
with st.expander("Ver el informe tal como lo recibe el sistema (JSON)"):
    st.json(t)
