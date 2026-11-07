"""Alertas: la bandeja del analista y la ficha de cada alerta. Dueño: PERSONA A.

Dos vistas a pantalla completa, una cada vez:
  · Bandeja: cifras clave, filtros en una fila y la tabla a todo el ancho. Pulsar una fila abre su ficha.
  · Ficha: barra de progreso de los 5 pasos y dos columnas, «La investigación» (qué ha pasado, qué ha
    comprobado el sistema) y «La decisión» (qué concluye, cuánto importa, plan de la IA, qué decides tú).

La alerta abierta se guarda en st.session_state["cola_open"]; "selected_alert" la comparten Informe y
Acciones. Enlace directo a una ficha: /cola?alerta=ALR-...
"""
import time

import pandas as pd
import streamlit as st

from core import data, store, ui

rows = data.load_results()
ids = [r["alert_id"] for r in rows]
if (qa := st.query_params.get("alerta")) and qa in ids:
    st.session_state["cola_open"] = st.session_state["selected_alert"] = qa
    del st.query_params["alerta"]
if not rows:
    st.title("Alertas")
    ui.empty_state("alertas en la bandeja")


def open_alert(alert_id: str) -> None:
    st.session_state["cola_open"] = st.session_state["selected_alert"] = alert_id


def back_to_list() -> None:
    st.session_state["cola_open"] = None
    st.session_state["cola_tabla_v"] = st.session_state.get("cola_tabla_v", 0) + 1  # limpia la selección


# ============================================================================ BANDEJA
def render_list() -> None:
    waiting = [r for r in rows if r["decision"] == "escalate" and not r["review"]]
    st.title("Alertas")
    st.markdown('<p class="muted">Cada fila es un aviso de una herramienta de seguridad que el sistema ya ha '
                "revisado. Pulsa una para ver qué ha pasado, en qué se basa la conclusión y decidir.</p>",
                unsafe_allow_html=True)

    m = st.columns(4)
    m[0].metric("Esperan a una persona", len(waiting), help="Escaladas a N2 y todavía sin revisar.")
    m[1].metric("Se cierran solas", sum(r["decision"] == "close" for r in rows),
                help="El sistema concluye que no hace falta nadie más y lo deja justificado.")
    m[2].metric("Revisadas por una persona", sum(bool(r["review"]) for r in rows))
    m[3].metric("Ataques reales", sum(r["verdict"] == "true_positive" for r in rows))

    f1, f2, f3, f4 = st.columns([3, 3, 3, 3], vertical_alignment="bottom")
    dec = f1.selectbox("Mostrar", ["todas", "escalate", "close"], key="cola_dec",
                       format_func=lambda d: {"todas": "Todas", "escalate": "Necesitan a una persona",
                                              "close": "Se cierran solas"}[d])
    ver = f2.multiselect("Conclusión", ui.VERDICT_ORDER, key="cola_ver", placeholder="Todas",
                         format_func=lambda v: ui.VERDICT_LABEL[v])
    sev = f3.multiselect("Gravedad", list(reversed(list(ui.SEVERITY_LABEL))), key="cola_sev", placeholder="Todas",
                         format_func=lambda s: ui.SEVERITY_LABEL[s].capitalize())
    q = f4.text_input("Buscar", placeholder="equipo, usuario, IP, regla…", key="cola_q").lower()
    filt = [r for r in rows if (dec in (None, "todas") or r["decision"] == dec)
            and (not ver or r["verdict"] in ver) and (not sev or r["severity"] in sev)
            and (not q or q in str(r["alert"]).lower())]

    df = pd.DataFrame([{
        "Gravedad": ui.SEVERITY_LABEL.get(r["severity"], r["severity"]),
        "Cuándo": ui.fmt_time(r["created_at"])[5:16],
        "Qué ha detectado": r["rule_name"],
        "Origen": r["source_product"],
        "Conclusión": ui.VERDICT_LABEL[r["verdict"]],
        "Propuesta": ui.DECISION_LABEL[r["decision"]],
        "Revisada": f"✓ {r['review']['analyst']}" if r["review"] else "",
    } for r in filt], columns=["Gravedad", "Cuándo", "Qué ha detectado", "Origen", "Conclusión", "Propuesta",
                               "Revisada"])
    event = st.dataframe(ui.style_queue(df), hide_index=True, use_container_width=True,
                         height=min(600, 38 + 35 * max(1, len(df))), on_select="rerun", selection_mode="single-row",
                         key=f"cola_tabla_{st.session_state.get('cola_tabla_v', 0)}",
                         column_config={"Gravedad": st.column_config.TextColumn(width="small"),
                                        "Qué ha detectado": st.column_config.TextColumn(width="large")})
    st.caption(f"{len(filt)} de {len(rows)} alertas · pulsa una fila para abrirla")
    if event.selection.rows:
        open_alert(filt[event.selection.rows[0]]["alert_id"])
        st.rerun()


# ============================================================================ FICHA
def render_detail(r: dict) -> None:
    a = r["alert"]
    pos = ids.index(r["alert_id"])
    n1, n2, n3, _ = st.columns([2, 1, 1, 4])
    if n1.button("← Volver a la bandeja", key="cola_back", use_container_width=True):
        back_to_list(); st.rerun()
    if n2.button("‹ Anterior", key="cola_prev", disabled=pos == 0, use_container_width=True):
        open_alert(ids[pos - 1]); st.rerun()
    if n3.button("Siguiente ›", key="cola_next", disabled=pos == len(ids) - 1, use_container_width=True):
        open_alert(ids[pos + 1]); st.rerun()

    # --- cabecera
    st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.verdict_badge(r['verdict'])}"
                f"{ui.example_tag(r, 'verdict')}", unsafe_allow_html=True)
    st.title(r["rule_name"], anchor=False)
    st.markdown(f'<p class="big"><b>El sistema concluye:</b> {ui.esc(ui.VERDICT_HELP[r["verdict"]])} '
                f'<b>Propone {ui.esc(ui.DECISION_VERB[r["decision"]])}:</b> {ui.esc(ui.DECISION_HELP[r["decision"]])}</p>',
                unsafe_allow_html=True)
    mitre = a.get("mitre") or {}
    st.caption(f"{ui.fmt_time(r['created_at'])} · origen {r['source_product']} · alerta {r['alert_id']} · "
               f"regla {r['rule_id']} · técnica MITRE {mitre.get('technique_id', '—')} {mitre.get('technique', '')}")
    ui.stepper(r)

    if r["injection_flags"]:
        st.error("**Intento de engañar al sistema.** El contenido de esta alerta incluye instrucciones dirigidas a "
                 "la clasificación automática. No se han obedecido: la alerta se trata como más sospechosa, no menos.",
                 icon="⚠️")
        for f in r["injection_flags"]:
            st.code(f["excerpt"], language=None, wrap_lines=True)

    left, right = st.columns([6, 5], gap="large")

    # --- la investigación
    with left:
        ui.eyebrow("La investigación")
        with st.container(border=True):
            ui.step(1, "Qué ha pasado", "Lo que vio la herramienta que lanzó el aviso.")
            st.text(a.get("description", ""))
            ents = ui.entities_table(a)
            if not ents.empty:
                st.dataframe(ents, hide_index=True, use_container_width=True)
            with st.expander("Datos originales de la alerta"):
                st.json(a.get("evidence") or {})

        with st.container(border=True):
            h, b = st.columns([4, 1], vertical_alignment="center")
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
                n_logs = len(r["related_logs"])
                with st.expander("Ver el registro de actividad relacionado" if n_logs == 1
                                 else f"Ver los {n_logs} registros de actividad relacionados"):
                    st.dataframe(r["related_logs"], hide_index=True, use_container_width=True)

    # --- la decisión
    with right:
        ui.eyebrow("La decisión")
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
            ui.step(4, "Cuánto importa", "Combina lo grave que es la regla con lo importante que es el equipo "
                    "afectado, como manda la política del SOC.")
            st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.esc(ui.SEVERITY_HELP[r['severity']])}",
                        unsafe_allow_html=True)
            with st.expander("Ver cómo se ha calculado"):
                st.caption(r["severity_rationale"])
                st.dataframe(ui.severity_matrix(r["rule_severity"], r["asset_criticality"]), use_container_width=True)
                st.caption(f"Fila: gravedad de la regla ({ui.SEVERITY_LABEL.get(r['rule_severity'], r['rule_severity'])})."
                           f" Columna: importancia del equipo ({r['asset_criticality'] or 'no está en el inventario'}).")

        # Plan de acción redactado por el LLM del back (assistant.py), como ayuda antes de decidir
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
                           + f" · {rv['at'].replace('T', ' ')[:16]} UTC"
                           + (f"  \nNota: {ui.md(rv['note'])}" if rv["note"] else ""))
                u1, u2 = st.columns(2)
                if u1.button("Deshacer la decisión", key="cola_undo", use_container_width=True):
                    store.delete_review(r["alert_id"])
                    st.rerun()
                if u2.button("Ver el informe para N2", key="cola_ticket_after", use_container_width=True):
                    st.switch_page("views/ticket.py")
            else:
                st.markdown(f"El sistema propone: {ui.decision_badge(r['decision'])} &nbsp; "
                            f"<span class='muted'>{ui.esc(ui.DECISION_HELP[r['decision']])}</span>",
                            unsafe_allow_html=True)
                other = "close" if r["decision"] == "escalate" else "escalate"
                c1, c2 = st.columns(2)
                analyst = c1.text_input("Tu nombre", key="cola_analyst", placeholder="p. ej. Ana García")
                note = c2.text_input("Nota (opcional)", key="cola_note", placeholder="por qué decides esto")
                b1, b2 = st.columns(2)
                if b1.button("✓ De acuerdo", type="primary", help=f"Aceptar la propuesta: {ui.DECISION_VERB[r['decision']]}",
                             disabled=not analyst, key="cola_ok", use_container_width=True):
                    store.save_review(r["alert_id"], r["decision"], analyst, note)
                    st.rerun()
                if b2.button(f"✗ Mejor {'cerrar' if other == 'close' else 'escalar'}", disabled=not analyst, key="cola_fix",
                             use_container_width=True):
                    store.save_review(r["alert_id"], other, analyst, note)
                    st.rerun()
                if not analyst:
                    st.caption("Escribe tu nombre para poder decidir.")


current = data.get_result(st.session_state["cola_open"]) if st.session_state.get("cola_open") in ids else None
if current:
    render_detail(current)
else:
    render_list()
