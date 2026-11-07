"""Cola de triaje + investigación de una alerta en 5 pasos + decisión de la persona.

Dueño: PERSONA A. A la izquierda la cola, a la derecha la alerta seleccionada.
"""
import time

import pandas as pd
import streamlit as st

from core import data, store, ui

rows = data.load_results()
pending = sum(r["decision"] == "escalate" and not r["review"] for r in rows)

st.title("Cola de triaje")
st.caption(f"{len(rows)} alertas · {pending} escaladas esperan a una persona · "
           f"{sum(bool(r['review']) for r in rows)} revisadas")

left, right = st.columns([5, 6], gap="large")

# ============================================================================ cola
with left:
    dec = st.segmented_control("Propuesta", ["todas", "escalate", "close"], default="todas", key="cola_dec",
                               format_func=lambda d: "Todas" if d == "todas" else ui.DECISION_LABEL[d])
    ver = st.pills("Veredicto", ui.VERDICT_ORDER, selection_mode="multi", key="cola_ver",
                   format_func=lambda v: ui.VERDICT_LABEL[v])
    q = st.text_input("Buscar", placeholder="regla, ID, usuario, host…", key="cola_q",
                      label_visibility="collapsed").lower()
    filt = [r for r in rows if (dec in (None, "todas") or r["decision"] == dec)
            and (not ver or r["verdict"] in ver) and (not q or q in str(r["alert"]).lower())]

    df = pd.DataFrame([{
        "Severidad": ui.SEVERITY_LABEL.get(r["severity"], r["severity"]),
        "Hora": ui.fmt_time(r["created_at"])[5:16],
        "Regla": r["rule_name"],
        "Veredicto": ui.VERDICT_LABEL[r["verdict"]],
        "Propuesta": ("⬆ " if r["decision"] == "escalate" else "") + ui.DECISION_LABEL[r["decision"]],
        "✓": "✓" if r["review"] else "",
    } for r in filt], columns=["Severidad", "Hora", "Regla", "Veredicto", "Propuesta", "✓"])
    st.caption(f"{len(filt)} de {len(rows)} alertas")
    event = st.dataframe(ui.style_queue(df), hide_index=True, use_container_width=True, height=620,
                         on_select="rerun", selection_mode="single-row", key="cola_tabla",
                         column_config={"Regla": st.column_config.TextColumn(width="medium"),
                                        "✓": st.column_config.TextColumn(width="small", help="Revisada por una persona")})
    if event.selection.rows:
        st.session_state["selected_alert"] = filt[event.selection.rows[0]]["alert_id"]

default = next((r for r in rows if r["decision"] == "escalate" and r["verdict"] == "true_positive"), rows[0])
r = data.get_result(st.session_state.get("selected_alert") or default["alert_id"]) or default
a = r["alert"]

# ============================================================================ detalle
with right:
    with st.container(border=True):
        st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.verdict_badge(r['verdict'])} &nbsp; "
                    f"{ui.decision_badge(r['decision'])}", unsafe_allow_html=True)
        st.subheader(r["rule_name"], anchor=False)
        mitre = a.get("mitre") or {}
        st.caption(f"`{r['alert_id']}` · {ui.fmt_time(r['created_at'])} · {r['source_product']} · {r['rule_id']} · "
                   f"runbook {a.get('runbook') or '—'} · {mitre.get('technique_id', '')} {mitre.get('technique', '')}")
        if r["example_fields"]:
            st.caption("Veredicto, propuesta y acciones son datos de ejemplo hasta que el back los genere.")

    if r["injection_flags"]:
        st.error("**Intento de manipulación.** El contenido de esta alerta da órdenes al sistema de clasificación. "
                 "No se han obedecido: la alerta se trata como más sospechosa, no menos.", icon="⚠️")
        for f in r["injection_flags"]:
            st.code(f"{f['field']}: {f['excerpt']}", language=None, wrap_lines=True)

    # --- 1
    with st.container(border=True):
        st.markdown("**1 · Qué detectó la regla**")
        st.text(a.get("description", ""))
        ents = [(k, v.get("hostname") or v.get("upn") or v.get("name") or v.get("customer_id") or str(v))
                if isinstance(v, dict) else (k, str(v))
                for k, vals in (a.get("entities") or {}).items() for v in (vals or [])]
        if ents:
            st.dataframe(pd.DataFrame(ents, columns=["Entidad", "Valor"]), hide_index=True, use_container_width=True)
        with st.expander("Evidencia de la alerta"):
            st.json(a.get("evidence") or {})

    # --- 2
    with st.container(border=True):
        h, b = st.columns([4, 2])
        h.markdown(f"**2 · Qué consultó el sistema** · {len(r['queries'])} consultas a la API del SOC")
        replay = b.button("▶ Repetir", key="cola_replay", use_container_width=True,
                          help="Muestra las consultas una a una, como las hizo el sistema")
        box = st.empty()
        if replay:
            for i in range(1, len(r["queries"]) + 1):
                with box.container():
                    ui.query_list(r["queries"][:i])
                time.sleep(0.5)
        else:
            with box.container():
                ui.query_list(r["queries"])
        if r["related_logs"]:
            with st.expander(f"Logs relacionados (±24 h) · {len(r['related_logs'])}"):
                st.dataframe(r["related_logs"], hide_index=True, use_container_width=True)

    # --- 3
    with st.container(border=True):
        st.markdown(f"**3 · Veredicto** {ui.example_tag(r, 'verdict')}", unsafe_allow_html=True)
        c1, c2 = st.columns([2, 3])
        c1.markdown(ui.verdict_badge(r["verdict"]), unsafe_allow_html=True)
        if r["confidence"] is not None:
            c2.progress(float(r["confidence"]), text=f"confianza {round(r['confidence'] * 100)} %")
        st.text(r["justification"] or "El back todavía no da justificación.")
        if r["open_questions"]:
            with st.expander(f"Lo que no he podido resolver · {len(r['open_questions'])}", expanded=r["verdict"] == "needs_more_info"):
                for oq in r["open_questions"]:
                    st.markdown(f"- {ui.md(oq)}")

    # --- 4
    with st.container(border=True):
        st.markdown("**4 · Severidad final** · matriz §2 de la política")
        st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; <small>{ui.md(r['severity_rationale'])}</small>",
                    unsafe_allow_html=True)
        st.dataframe(ui.severity_matrix(r["rule_severity"], r["asset_criticality"]), use_container_width=True)
        st.caption(f"Fila: severidad de la regla ({ui.SEVERITY_LABEL.get(r['rule_severity'], r['rule_severity'])}). "
                   f"Columna: criticidad del activo ({r['asset_criticality'] or 'sin activo en la CMDB'}).")

    # --- 5
    with st.container(border=True):
        st.markdown(f"**5 · Decisión de la persona** {ui.example_tag(r, 'decision')}", unsafe_allow_html=True)
        st.markdown(f"El sistema propone: {ui.decision_badge(r['decision'])}", unsafe_allow_html=True)
        rv = r["review"]
        if rv:
            changed = rv["decision"] != r["decision"]
            st.success(f"**{rv['analyst']}** decidió **{ui.DECISION_LABEL[rv['decision']]}**"
                       + (" (corrigió al sistema)" if changed else " (aceptó la propuesta)")
                       + f" · {rv['at'].replace('T', ' ')[:16]} UTC" + (f"  \nNota: {ui.md(rv['note'])}" if rv["note"] else ""))
            u1, u2 = st.columns(2)
            if u1.button("Deshacer decisión", key="cola_undo", use_container_width=True):
                store.delete_review(r["alert_id"])
                st.rerun()
            if u2.button("Ver ticket para N2", key="cola_ticket_after", use_container_width=True):
                st.switch_page("views/ticket.py")
        else:
            other = "close" if r["decision"] == "escalate" else "escalate"
            analyst = st.text_input("Analista", key="cola_analyst", placeholder="tu nombre")
            note = st.text_input("Nota (opcional)", key="cola_note")
            b1, b2 = st.columns(2)
            if b1.button(f"Aceptar: {ui.DECISION_LABEL[r['decision']]}", type="primary", disabled=not analyst,
                         key="cola_ok", use_container_width=True):
                store.save_review(r["alert_id"], r["decision"], analyst, note)
                st.rerun()
            if b2.button(f"Corregir: {ui.DECISION_LABEL[other]}", disabled=not analyst, key="cola_fix",
                         use_container_width=True):
                store.save_review(r["alert_id"], other, analyst, note)
                st.rerun()
            st.caption("El sistema no ejecuta nada por su cuenta: solo propone. Escribe tu nombre para decidir.")
