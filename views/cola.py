"""Alertas: la bandeja del analista + la investigación de una alerta en 5 pasos. Dueño: PERSONA A.

A la izquierda la bandeja; a la derecha la alerta abierta, contada para alguien de fuera:
qué ha pasado, qué ha comprobado el sistema, qué concluye, cuánto importa y qué decides tú.
"""
import time

import pandas as pd
import streamlit as st

from core import data, store, ui

rows = data.load_results()
# Enlace directo a una alerta: /cola?alerta=ALR-...
if (qa := st.query_params.get("alerta")) and any(r["alert_id"] == qa for r in rows):
    st.session_state["selected_alert"] = qa
    del st.query_params["alerta"]
if not rows:
    st.title("Alertas")
    ui.empty_state("alertas en la bandeja")
waiting = [r for r in rows if r["decision"] == "escalate" and not r["review"]]

st.title("Alertas")
st.markdown(f'<p class="muted">Cada fila es un aviso de una herramienta de seguridad, ya revisado por el sistema. '
            f'Ahora mismo <b>{len(waiting)} esperan a una persona</b>. Pulsa una fila para ver la investigación.</p>',
            unsafe_allow_html=True)

left, right = st.columns([1, 1], gap="large")

# ============================================================================ bandeja
with left:
    dec = st.segmented_control("Mostrar", ["todas", "escalate", "close"], default="todas", key="cola_dec",
                               format_func=lambda d: {"todas": "Todas", "escalate": "Necesitan a una persona",
                                                      "close": "Se cierran solas"}[d])
    ver = st.pills("Conclusión", ui.VERDICT_ORDER, selection_mode="multi", key="cola_ver",
                   format_func=lambda v: ui.VERDICT_LABEL[v])
    q = st.text_input("Buscar", placeholder="Buscar por equipo, usuario, IP, regla…", key="cola_q",
                      label_visibility="collapsed").lower()
    filt = [r for r in rows if (dec in (None, "todas") or r["decision"] == dec)
            and (not ver or r["verdict"] in ver) and (not q or q in str(r["alert"]).lower())]

    df = pd.DataFrame([{
        "Gravedad": ui.SEVERITY_LABEL.get(r["severity"], r["severity"]),
        "Qué ha detectado": r["rule_name"],
        "Conclusión": ui.VERDICT_LABEL[r["verdict"]],
        "Propuesta": ("Escalar" if r["decision"] == "escalate" else "Cerrar") + (" ✓" if r["review"] else ""),
    } for r in filt], columns=["Gravedad", "Qué ha detectado", "Conclusión", "Propuesta"])
    event = st.dataframe(ui.style_queue(df), hide_index=True, use_container_width=True,
                         height=min(640, 38 + 35 * max(1, len(df))),
                         on_select="rerun", selection_mode="single-row", key="cola_tabla",
                         column_config={"Gravedad": st.column_config.TextColumn(width="small"),
                                        "Qué ha detectado": st.column_config.TextColumn(width="medium"),
                                        "Propuesta": st.column_config.TextColumn(width="small",
                                            help="✓ = ya la ha revisado una persona")})
    st.caption(f"{len(filt)} de {len(rows)} alertas")
    if event.selection.rows:
        st.session_state["selected_alert"] = filt[event.selection.rows[0]]["alert_id"]

default = next((r for r in rows if r["decision"] == "escalate" and r["verdict"] == "true_positive"), rows[0])
r = data.get_result(st.session_state.get("selected_alert") or default["alert_id"]) or default
a = r["alert"]

# ============================================================================ investigación
with right:
    with st.container(border=True):
        st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.verdict_badge(r['verdict'])}"
                    f"{ui.example_tag(r, 'verdict')}", unsafe_allow_html=True)
        st.subheader(r["rule_name"], anchor=False)
        st.markdown(f"**El sistema concluye:** {ui.VERDICT_HELP[r['verdict']]} "
                    f"**Propone {ui.DECISION_VERB[r['decision']]}:** {ui.DECISION_HELP[r['decision']]}")
        mitre = a.get("mitre") or {}
        st.caption(f"{ui.fmt_time(r['created_at'])} · origen {r['source_product']} · alerta {r['alert_id']} · "
                   f"regla {r['rule_id']} · técnica MITRE {mitre.get('technique_id', '—')}")

    if r["injection_flags"]:
        st.error("**Intento de engañar al sistema.** El contenido de esta alerta incluye instrucciones dirigidas a "
                 "la clasificación automática. No se han obedecido: la alerta se trata como más sospechosa, no menos.",
                 icon="⚠️")
        for f in r["injection_flags"]:
            st.code(f["excerpt"], language=None, wrap_lines=True)

    with st.container(border=True):
        ui.step(1, "Qué ha pasado", "Lo que vio la herramienta que lanzó el aviso.")
        st.text(a.get("description", ""))
        ents = ui.entities_table(a)
        if not ents.empty:
            st.dataframe(ents, hide_index=True, use_container_width=True)
        with st.expander("Datos originales de la alerta"):
            st.json(a.get("evidence") or {})

    with st.container(border=True):
        h, b = st.columns([5, 2], vertical_alignment="center")
        with h:
            ui.step(2, "Qué ha comprobado el sistema",
                    f"{len(r['queries'])} consultas a las fuentes de la empresa, con lo que encontró en cada una.")
        replay = b.button("▶ Repetir", key="cola_replay", use_container_width=True,
                          help="Vuelve a mostrar las comprobaciones una a una, en el orden en que se hicieron")
        box = st.empty()
        if replay:
            for i in range(1, len(r["queries"]) + 1):
                with box.container():
                    ui.query_list(r["queries"], limit=i)
                time.sleep(0.6)
        else:
            with box.container():
                ui.query_list(r["queries"])
        st.caption("🟢 encontrado · 🟡 no hay datos (que no haya datos no significa que sea seguro) · 🔴 error")
        if r["related_logs"]:
            n_logs = len(r['related_logs'])
            with st.expander("Ver el registro de actividad relacionado" if n_logs == 1
                             else f"Ver los {n_logs} registros de actividad relacionados"):
                st.dataframe(r["related_logs"], hide_index=True, use_container_width=True)

    with st.container(border=True):
        ui.step(3, "Qué concluye y por qué", "La conclusión y las pruebas en las que se apoya.",
                ui.example_tag(r, "verdict"))
        c1, c2 = st.columns([2, 3], vertical_alignment="center")
        c1.markdown(ui.verdict_badge(r["verdict"]), unsafe_allow_html=True)
        if r["confidence"] is not None:
            c2.progress(float(r["confidence"]), text=f"Seguridad de la conclusión: {round(r['confidence'] * 100)} %")
        st.markdown(f"> {ui.md(r['justification'] or 'El motor todavía no da una justificación.')}")
        if r["open_questions"]:
            with st.expander(f"Lo que no ha podido comprobar ({len(r['open_questions'])})",
                             expanded=r["verdict"] == "needs_more_info"):
                for oq in r["open_questions"]:
                    st.markdown(f"- {ui.md(oq)}")

    with st.container(border=True):
        ui.step(4, "Cuánto importa", "Combina lo grave que es la regla con lo importante que es el equipo afectado, "
                "como manda la política del SOC.")
        st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.esc(ui.SEVERITY_HELP[r['severity']])}",
                    unsafe_allow_html=True)
        with st.expander("Ver cómo se ha calculado"):
            st.caption(r["severity_rationale"])
            st.dataframe(ui.severity_matrix(r["rule_severity"], r["asset_criticality"]), use_container_width=True)
            st.caption(f"Fila: gravedad de la regla ({ui.SEVERITY_LABEL.get(r['rule_severity'], r['rule_severity'])}). "
                       f"Columna: importancia del equipo ({r['asset_criticality'] or 'no está en el inventario'}).")

    # --- Plan de acción redactado por el LLM del back (assistant.py), como ayuda antes de decidir
    with st.container(border=True):
        llm_ok, llm_info = data.llm_status()
        ui.step("✦", "Borrador del plan de acción",
                "Un modelo de lenguaje resume la situación y propone qué hacer. Es una ayuda para decidir, "
                "no una decisión: puede equivocarse y no ejecuta nada.")
        plans = st.session_state.setdefault("cola_plans", {})
        if r["alert_id"] in plans:
            st.markdown(ui.llm_md(plans[r["alert_id"]]))
            st.caption(f"Redactado por IA · {llm_info} · los datos de la alerta se le pasan como no fiables, "
                       "así que no obedece instrucciones escondidas en ellos.")
        elif llm_ok:
            if st.button("Redactar plan con la IA", key="cola_plan_btn", icon=":material/auto_awesome:"):
                try:
                    with st.spinner("Redactando…"):
                        text = st.write_stream(data.action_plan(r))
                    plans[r["alert_id"]] = text if isinstance(text, str) else "".join(map(str, text))
                    st.rerun()
                except Exception as exc:  # pasarela caída, timeout…
                    st.error(f"No se ha podido redactar el plan: {exc}")
            st.caption(f"Tarda unos segundos · {llm_info}.")
        else:
            st.caption(f"No disponible: {llm_info} El resto del triaje funciona igual sin IA.")

    with st.container(border=True):
        ui.step(5, "Qué decides tú", "El sistema solo propone. La decisión, y quién la toma, queda registrada.",
                ui.example_tag(r, "decision"))
        rv = r["review"]
        if rv:
            changed = rv["decision"] != r["decision"]
            st.success(f"**{rv['analyst']}** decidió **{ui.DECISION_VERB[rv['decision']]}**"
                       + (" y corrigió al sistema" if changed else ", como proponía el sistema")
                       + f" · {rv['at'].replace('T', ' ')[:16]} UTC" + (f"  \nNota: {ui.md(rv['note'])}" if rv["note"] else ""))
            u1, u2 = st.columns(2)
            if u1.button("Deshacer la decisión", key="cola_undo", use_container_width=True):
                store.delete_review(r["alert_id"])
                st.rerun()
            if u2.button("Ver el informe para N2", key="cola_ticket_after", use_container_width=True):
                st.switch_page("views/ticket.py")
        else:
            st.markdown(f"El sistema propone: {ui.decision_badge(r['decision'])} &nbsp; "
                        f"<span class='muted'>{ui.esc(ui.DECISION_HELP[r['decision']])}</span>", unsafe_allow_html=True)
            other = "close" if r["decision"] == "escalate" else "escalate"
            c1, c2 = st.columns(2)
            analyst = c1.text_input("Tu nombre", key="cola_analyst", placeholder="p. ej. Ana García")
            note = c2.text_input("Nota (opcional)", key="cola_note", placeholder="por qué decides esto")
            b1, b2 = st.columns(2)
            if b1.button(f"✓ De acuerdo: {ui.DECISION_VERB[r['decision']]}", type="primary",
                         disabled=not analyst, key="cola_ok", use_container_width=True):
                store.save_review(r["alert_id"], r["decision"], analyst, note)
                st.rerun()
            if b2.button(f"✗ No, mejor {ui.DECISION_VERB[other]}", disabled=not analyst, key="cola_fix",
                         use_container_width=True):
                store.save_review(r["alert_id"], other, analyst, note)
                st.rerun()
            if not analyst:
                st.caption("Escribe tu nombre para poder decidir.")
