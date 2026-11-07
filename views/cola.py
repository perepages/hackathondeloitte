"""Cola de triaje + detalle de una alerta en 5 pasos + decisión de la persona.

Dueño: PERSONA A. Punto de partida que ya funciona con el fixture; a partir de aquí, diseño.
Pendiente (ver el plan de frontend):
  - TODO A: diseño de la cola (colores por severidad, filtros en una fila, contador).
  - TODO A: botón «Repetir la investigación» que muestre las consultas una a una.
  - TODO A: pulir el paso 5 (quién decidió y cuándo, deshacer).
Referencia visual: demo/triaje_demo.html (maqueta HTML).
"""
import pandas as pd
import streamlit as st

from core import data, store, ui

st.title("Cola de triaje")
rows = data.load_results()

# ----------------------------------------------------------------------------- filtros
f1, f2, f3 = st.columns([1, 1, 2])
dec = f1.selectbox("Decisión", ["todas", "escalate", "close"],
                   format_func=lambda d: "Todas" if d == "todas" else ui.DECISION_LABEL[d], key="cola_dec")
ver = f2.selectbox("Veredicto", ["todos"] + ui.VERDICT_ORDER,
                   format_func=lambda v: "Todos" if v == "todos" else ui.VERDICT_LABEL[v], key="cola_ver")
q = f3.text_input("Buscar", placeholder="regla, ID, usuario, host…", key="cola_q").lower()
filt = [r for r in rows if (dec == "todas" or r["decision"] == dec) and (ver == "todos" or r["verdict"] == ver)
        and (not q or q in str(r["alert"]).lower())]

df = pd.DataFrame([{
    "Hora": ui.fmt_time(r["created_at"]), "Regla": r["rule_name"], "Producto": r["source_product"],
    "Severidad": ui.SEVERITY_LABEL.get(r["severity"], r["severity"]), "Veredicto": ui.VERDICT_LABEL[r["verdict"]],
    "Propuesta": ui.DECISION_LABEL[r["decision"]], "Revisada": "✓" if r["review"] else "", "ID": r["alert_id"],
} for r in filt])
st.caption(f"{len(filt)} de {len(rows)} alertas")
event = st.dataframe(df, hide_index=True, use_container_width=True, height=300,
                     on_select="rerun", selection_mode="single-row", key="cola_tabla")
if event.selection.rows:
    st.session_state["selected_alert"] = filt[event.selection.rows[0]]["alert_id"]

default = next((r for r in rows if r["decision"] == "escalate" and r["verdict"] == "true_positive"), rows[0])
r = data.get_result(st.session_state.get("selected_alert") or default["alert_id"]) or default
a = r["alert"]

# ----------------------------------------------------------------------------- cabecera
st.divider()
st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; `{r['alert_id']}` &nbsp; "
            f"<small>{ui.fmt_time(r['created_at'])} · {ui.md(r['source_product'])} · {ui.md(r['rule_id'])} · "
            f"runbook {ui.md(a.get('runbook') or '—')}</small>", unsafe_allow_html=True)
st.subheader(r["rule_name"])
mitre = a.get("mitre") or {}
st.caption(f"{mitre.get('tactic', '')} · {mitre.get('technique_id', '')} {mitre.get('technique', '')}")

if r["injection_flags"]:
    st.warning("**Posible manipulación:** este contenido intenta dar órdenes al sistema de clasificación. "
               "No se ha obedecido y sube la sospecha.", icon="⚠️")
    for f in r["injection_flags"]:
        st.code(f"{f['field']}: {f['excerpt']}", language=None, wrap_lines=True)

# ----------------------------------------------------------------------------- 5 pasos
with st.container(border=True):
    st.markdown("**1 · Qué detectó la regla**")
    st.text(a.get("description", ""))
    ents = [f"{k}: {v.get('hostname') or v.get('upn') or v.get('name') or v.get('customer_id') or v}"
            if isinstance(v, dict) else f"{k}: {v}"
            for k, vals in (a.get("entities") or {}).items() for v in (vals or [])]
    st.text(" · ".join(ents) or "sin entidades")
    st.json(a.get("evidence") or {}, expanded=False)

with st.container(border=True):
    st.markdown("**2 · Qué consultó el sistema a la API del SOC**")
    ui.query_list(r["queries"])
    if r["related_logs"]:
        with st.expander(f"Logs relacionados ({len(r['related_logs'])})"):
            st.dataframe(r["related_logs"], hide_index=True, use_container_width=True)

with st.container(border=True):
    st.markdown(f"**3 · Veredicto** {ui.example_tag(r, 'verdict')}", unsafe_allow_html=True)
    st.markdown(ui.verdict_badge(r["verdict"]), unsafe_allow_html=True)
    if r["confidence"] is not None:
        st.progress(float(r["confidence"]), text=f"confianza {round(r['confidence'] * 100)} %")
    st.text(r["justification"] or "El back todavía no da justificación.")
    if r["open_questions"]:
        st.markdown("Lo que no he podido resolver:")
        for oq in r["open_questions"]:
            st.markdown(f"- {ui.md(oq)}")

with st.container(border=True):
    st.markdown("**4 · Severidad final (matriz §2 de la política)**")
    st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; <small>{ui.md(r['severity_rationale'])}</small>",
                unsafe_allow_html=True)
    st.dataframe(ui.severity_matrix(r["rule_severity"], r["asset_criticality"]), use_container_width=False)

with st.container(border=True):
    st.markdown(f"**5 · Decisión de la persona** {ui.example_tag(r, 'decision')}", unsafe_allow_html=True)
    st.markdown(f"El sistema propone: {ui.decision_badge(r['decision'])}", unsafe_allow_html=True)
    if r["review"]:
        rv = r["review"]
        st.success(f"Revisada por {rv['analyst']} ({rv['at']}): {ui.DECISION_LABEL[rv['decision']]}"
                   + (f" · {rv['note']}" if rv["note"] else ""))
    other = "close" if r["decision"] == "escalate" else "escalate"
    analyst = st.text_input("Analista", key="cola_analyst", placeholder="tu nombre")
    note = st.text_input("Nota (opcional)", key="cola_note")
    b1, b2 = st.columns(2)
    if b1.button(f"Aceptar: {ui.DECISION_LABEL[r['decision']]}", type="primary", disabled=not analyst, key="cola_ok"):
        store.save_review(r["alert_id"], r["decision"], analyst, note)
        st.rerun()
    if b2.button(f"Corregir: {ui.DECISION_LABEL[other]}", disabled=not analyst, key="cola_fix"):
        store.save_review(r["alert_id"], other, analyst, note)
        st.rerun()
    st.caption("El sistema no ejecuta ninguna contención: solo propone. Decide la persona.")
