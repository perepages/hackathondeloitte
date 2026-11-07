"""Alertas: la bandeja del analista y, debajo, la ficha de la alerta seleccionada. Dueño: PERSONA A.

Una sola pantalla:
  · Arriba la bandeja: cifras clave, filtros en una fila y la tabla, ordenada para elegir rápido
    (primero las que esperan a una persona y, dentro, las más graves).
  · Debajo la ficha de la alerta seleccionada: barra de progreso de los 5 pasos y dos columnas,
    «La investigación» y «La decisión». Al elegir otra fila, la página baja sola hasta la ficha.

La alerta abierta se guarda en st.session_state["cola_open"]; "selected_alert" la comparten Informe y
Acciones. Enlace directo a una alerta: /alertes?alerta=ALR-...
"""
import time

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from core import data, store, ui
from policy import criticality_ca

SEV_RANK = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "informational"])}

rows = data.load_results()
ids = [r["alert_id"] for r in rows]
if (qa := st.query_params.get("alerta")) and qa in ids:
    st.session_state["cola_open"] = st.session_state["selected_alert"] = qa
    del st.query_params["alerta"]


def title_with_refresh() -> None:
    """Título y botón «Actualitzar alertes» (también con la bandeja vacía: es cuando más falta hace)."""
    t1, t2 = st.columns([5, 1.4], vertical_alignment="bottom")
    t1.title("Alertes")
    if t2.button("Actualitzar alertes", key="cola_refresh", icon=":material/refresh:", use_container_width=True,
                 help="Torna a carregar la safata i, connectat a l'API, tria les alertes noves que hagin entrat"):
        try:
            bar = st.progress(0.0, text="Buscant alertes noves…") if data.MODE != "fixture" else None
            n = data.refresh(on_progress=(lambda i, t: bar.progress(i / t, text=f"Triant alertes noves: {i} de {t}"))
                             if bar else None)
            st.session_state["cola_refresh_msg"] = (f"{n} alerta(es) nova(es) a la safata." if n
                                                    else "La safata està al dia: no hi ha alertes noves.")
        except Exception as exc:  # p. ej. la API no responde
            st.session_state["cola_refresh_msg"] = f"No s'han pogut buscar alertes noves: {exc}"
        st.rerun()
    if msg := st.session_state.pop("cola_refresh_msg", None):
        st.toast(msg, icon=":material/refresh:")


if not rows:
    title_with_refresh()
    ui.empty_state("alertes a la safata")


def open_alert(alert_id: str) -> None:
    st.session_state["cola_open"] = st.session_state["selected_alert"] = alert_id


def sort_queue(items: list[dict]) -> list[dict]:
    """Primero lo que espera a una persona, luego lo más grave y, a igualdad, lo más reciente."""
    newest_first = sorted(items, key=lambda r: r["created_at"], reverse=True)
    return sorted(newest_first, key=lambda r: (not (r["decision"] == "escalate" and not r["review"]),
                                               SEV_RANK.get(r["severity"], 9)))


# ============================================================================ BANDEJA
def render_list() -> bool:
    """Pinta la bandeja. Devuelve True si el usuario acaba de elegir otra alerta."""
    waiting = [r for r in rows if r["decision"] == "escalate" and not r["review"]]
    title_with_refresh()
    st.markdown('<p class="muted">Cada fila és un avís d\'una eina de seguretat que el sistema ja ha '
                "revisat. Tria'n una i a sota veuràs què ha passat, en què es basa la conclusió i podràs decidir.</p>",
                unsafe_allow_html=True)

    m = st.columns(4)
    m[0].metric("Esperen una persona", len(waiting), help="Escalades a N2 i encara sense revisar.")
    m[1].metric("Es tanquen soles", sum(r["decision"] == "close" for r in rows),
                help="El sistema conclou que no cal ningú més i ho deixa justificat.")
    m[2].metric("Revisades per una persona", sum(bool(r["review"]) for r in rows))
    m[3].metric("Atacs reals", sum(r["verdict"] == "true_positive" for r in rows))

    f1, f2, f3, f4 = st.columns([3, 3, 3, 3], vertical_alignment="bottom")
    dec = f1.selectbox("Mostrar", ["todas", "escalate", "close"], key="cola_dec",
                       format_func=lambda d: {"todas": "Totes", "escalate": "Necessiten una persona",
                                              "close": "Es tanquen soles"}[d])
    ver = f2.multiselect("Conclusió", ui.VERDICT_ORDER, key="cola_ver", placeholder="Totes",
                         format_func=lambda v: ui.VERDICT_LABEL[v])
    sev = f3.multiselect("Gravetat", list(reversed(list(ui.SEVERITY_LABEL))), key="cola_sev", placeholder="Totes",
                         format_func=lambda s: ui.SEVERITY_LABEL[s].capitalize())
    q = f4.text_input("Cercar", placeholder="equip, usuari, IP, regla…", key="cola_q").lower()
    filt = sort_queue([r for r in rows if (dec in (None, "todas") or r["decision"] == dec)
                       and (not ver or r["verdict"] in ver) and (not sev or r["severity"] in sev)
                       and (not q or q in str(r["alert"]).lower())])
    st.session_state["cola_filtered"] = [r["alert_id"] for r in filt]

    # Selección de una sola alerta: se hace clic en cualquier celda de la fila (sin casillas cuadradas) y la
    # primera columna muestra un botón de opción (radio) dibujado: marcado en la abierta, vacío en el resto.
    changed = False
    cells = (((st.session_state.get("cola_tabla") or {}).get("selection") or {}).get("cells")) or []
    if cells and repr(cells[0]) != st.session_state.get("cola_last_cell"):  # un clic nuevo, no el de antes
        st.session_state["cola_last_cell"] = repr(cells[0])
        cell = cells[0]
        row = cell[0] if isinstance(cell, (list, tuple)) else (cell or {}).get("row")
        if isinstance(row, int) and 0 <= row < len(filt) and filt[row]["alert_id"] != st.session_state.get("cola_open"):
            open_alert(filt[row]["alert_id"])
            changed = True
    if st.session_state.get("cola_open") not in ids:  # per defecte, la primera de la safata (la més urgent)
        open_alert(filt[0]["alert_id"] if filt else ids[0])
    open_now = st.session_state.get("cola_open")

    df = pd.DataFrame([{
        " ": ui.RADIO_ON if r["alert_id"] == open_now else ui.RADIO_OFF,
        "Gravetat": ui.SEVERITY_LABEL.get(r["severity"], r["severity"]),
        "Estat": ("Espera una persona" if r["decision"] == "escalate" else "Tancada pel sistema")
                 if not r["review"] else f"Revisada per {r['review']['analyst']}",
        "Què ha detectat": r["rule_name"],
        "Conclusió": ui.VERDICT_LABEL[r["verdict"]],
        "Origen": r["source_product"],
        "Quan": ui.fmt_time(r["created_at"])[5:16],
    } for r in filt], columns=[" ", "Gravetat", "Estat", "Què ha detectat", "Conclusió", "Origen", "Quan"])
    st.dataframe(ui.style_queue(df), hide_index=True, use_container_width=True,
                 height=min(390, 38 + 35 * max(1, len(df))), on_select="rerun", selection_mode="single-cell",
                 key="cola_tabla",
                 column_config={" ": st.column_config.ImageColumn(width=44),
                                "Gravetat": st.column_config.TextColumn(width="small"),
                                "Què ha detectat": st.column_config.TextColumn(width="large")})
    st.caption(f"{len(filt)} de {len(rows)} alertes · fes clic en una fila per veure'n la fitxa a sota")
    return changed


# ============================================================================ FICHA
def render_detail(r: dict, scroll: bool) -> None:
    a = r["alert"]
    st.markdown('<div id="ficha"></div>', unsafe_allow_html=True)
    if scroll:  # baja hasta la ficha al elegir otra alerta
        components.html("<script>const f=window.parent.document.getElementById('ficha');"
                        "if(f){f.scrollIntoView({behavior:'smooth',block:'start'});}</script>", height=0)
    st.divider()
    ui.eyebrow("Alerta seleccionada")
    st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.verdict_badge(r['verdict'])}"
                f"{ui.example_tag(r, 'verdict')}", unsafe_allow_html=True)
    st.header(r["rule_name"], anchor=False)
    st.markdown(f'<p class="big"><b>El sistema conclou:</b> {ui.esc(ui.VERDICT_HELP[r["verdict"]])} '
                f'<b>Proposa {ui.esc(ui.DECISION_VERB[r["decision"]])}:</b> {ui.esc(ui.DECISION_HELP[r["decision"]])}</p>',
                unsafe_allow_html=True)
    mitre = a.get("mitre") or {}
    st.caption(f"{ui.fmt_time(r['created_at'])} · origen {r['source_product']} · alerta {r['alert_id']} · "
               f"regla {r['rule_id']} · tècnica MITRE {mitre.get('technique_id', '—')} {mitre.get('technique', '')}")
    ui.stepper(r)

    if r["injection_flags"]:
        st.error("**Intent d'enganyar el sistema.** El contingut d'aquesta alerta inclou instruccions adreçades a "
                 "la classificació automàtica. No s'han obeït: l'alerta es tracta com a més sospitosa, no menys.",
                 icon=":material/gpp_bad:")
        for f in r["injection_flags"]:
            st.code(f["excerpt"], language=None, wrap_lines=True)

    left, right = st.columns([6, 5], gap="large")

    # --- la investigación
    with left:
        ui.eyebrow("La investigació")
        with st.container(border=True):
            ui.step(1, "Què ha passat", "El que va veure l'eina que va llançar l'avís.")
            st.text(a.get("description", ""))
            ents = ui.entities_table(a)
            if not ents.empty:
                st.dataframe(ents, hide_index=True, use_container_width=True)
            with st.expander("Dades originals de l'alerta"):
                st.json(a.get("evidence") or {})

        with st.container(border=True):
            h, b = st.columns([4, 1], vertical_alignment="center")
            with h:
                ui.step(2, "Què ha comprovat el sistema",
                        f"{len(r['queries'])} consultes a les fonts de l'empresa, amb el que ha trobat a cadascuna.")
            replay = b.button("Repetir", key="cola_replay", icon=":material/replay:", use_container_width=True,
                              help="Torna a mostrar les comprovacions una a una, en l'ordre en què es van fer")
            box = st.empty()
            if replay:
                for i in range(1, len(r["queries"]) + 1):
                    with box.container():
                        ui.query_list(r["queries"], limit=i)
                    time.sleep(0.6)
            else:
                with box.container():
                    ui.query_list(r["queries"])
            ui.query_legend()
            if r["related_logs"]:
                n_logs = len(r["related_logs"])
                with st.expander("Veure el registre d'activitat relacionat" if n_logs == 1
                                 else f"Veure els {n_logs} registres d'activitat relacionats"):
                    st.dataframe(r["related_logs"], hide_index=True, use_container_width=True)

    # --- la decisión
    with right:
        ui.eyebrow("La decisió")
        with st.container(border=True):
            ui.step(3, "Què conclou i per què", "La conclusió i les proves en què es basa.",
                    ui.example_tag(r, "verdict"))
            c1, c2 = st.columns([2, 3], vertical_alignment="center")
            c1.markdown(ui.verdict_badge(r["verdict"]), unsafe_allow_html=True)
            if r["confidence"] is not None:
                c2.progress(float(r["confidence"]), text=f"Seguretat de la conclusió: {round(r['confidence'] * 100)} %")
            st.markdown(f"> {ui.md(r['justification'] or 'El sistema no ha donat cap justificació.')}")
            source = {"llm": "Proposta de la IA, revisada amb les regles de la política del SOC.",
                      "rules": "Proposta de les regles automàtiques (la IA no estava disponible o no ha respost bé)"
                      + (f" · regla: {r['rule_applied']}." if r.get("rule_applied") else ".")
                      }.get(r.get("decision_source"))
            if source:
                st.caption(source)
            if (so := r.get("second_opinion")) and so.get("verdict"):
                label = ui.VERDICT_LABEL.get(so["verdict"], so["verdict"])
                if so["verdict"] == r["verdict"]:
                    st.caption(f"Les regles arriben a la mateixa conclusió ({ui.md(so.get('rule', ''))}).")
                else:
                    st.caption(f"Les regles opinen una altra cosa: **{label}** ({ui.md(so.get('rule', ''))}). "
                               f"{ui.md(so.get('justification', ''))}")
            for note in r.get("decision_notes") or []:
                st.caption(f"Política del SOC: {ui.md(note)}")
            if r["open_questions"]:
                with st.expander(f"El que no ha pogut comprovar ({len(r['open_questions'])})",
                                 expanded=r["verdict"] == "needs_more_info"):
                    for oq in r["open_questions"]:
                        st.markdown(f"- {ui.md(oq)}")

        with st.container(border=True):
            ui.step(4, "Quant importa", "Combina com de greu és la regla amb com d'important és l'equip "
                    "afectat, tal com mana la política del SOC.")
            st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.esc(ui.SEVERITY_HELP[r['severity']])}",
                        unsafe_allow_html=True)
            with st.expander("Veure com s'ha calculat"):
                st.caption(r["severity_rationale"])
                st.dataframe(ui.severity_matrix(r["rule_severity"], r["asset_criticality"]), use_container_width=True)
                st.caption(f"Fila: gravetat de la regla ({ui.SEVERITY_LABEL.get(r['rule_severity'], r['rule_severity'])})."
                           f" Columna: importància de l'equip ({criticality_ca(r['asset_criticality']) or 'fora de l’inventari'}).")

        with st.container(border=True):
            ui.step(5, "Què decideixes tu", "El sistema només proposa. La decisió, i qui la pren, queda registrada.",
                    ui.example_tag(r, "decision"))
            rv = r["review"]
            if rv:
                changed = rv["decision"] != r["decision"]
                st.success(f"**{rv['analyst']}** va decidir **{ui.DECISION_VERB[rv['decision']]}**"
                           + (" i va corregir el sistema" if changed else ", com proposava el sistema")
                           + f" · {rv['at'].replace('T', ' ')[:16]} UTC"
                           + (f"  \nNota: {ui.md(rv['note'])}" if rv["note"] else ""))
                u1, u2 = st.columns(2)
                if u1.button("Desfer la decisió", key="cola_undo", use_container_width=True):
                    store.delete_review(r["alert_id"])
                    st.rerun()
                if u2.button("Veure l'informe per a N2", key="cola_ticket_after", use_container_width=True):
                    st.switch_page("views/informe_n2.py")
            else:
                st.markdown(f"El sistema proposa: {ui.decision_badge(r['decision'])} &nbsp; "
                            f"<span class='muted'>{ui.esc(ui.DECISION_HELP[r['decision']])}</span>",
                            unsafe_allow_html=True)
                other = "close" if r["decision"] == "escalate" else "escalate"
                c1, c2 = st.columns(2)
                analyst = c1.text_input("El teu nom", key="cola_analyst", placeholder="p. ex. Anna Garcia")
                note = c2.text_input("Nota (opcional)", key="cola_note", placeholder="per què ho decideixes")
                b1, b2 = st.columns(2)
                if b1.button("D'acord", icon=":material/check:", type="primary", help=f"Acceptar la proposta: {ui.DECISION_VERB[r['decision']]}",
                             disabled=not analyst, key="cola_ok", use_container_width=True):
                    store.save_review(r["alert_id"], r["decision"], analyst, note)
                    st.rerun()
                if b2.button(f"Millor {'tancar' if other == 'close' else 'escalar'}", icon=":material/undo:", disabled=not analyst, key="cola_fix",
                             use_container_width=True):
                    store.save_review(r["alert_id"], other, analyst, note)
                    st.rerun()
                if not analyst:
                    st.caption("Escriu el teu nom per poder decidir.")

    # --- plan de acción (ancho completo, debajo de las dos columnas)
    with st.container(border=True):
        llm_ok, llm_info = data.llm_status()
        ui.step("IA", "Esborrany del pla d'acció",
                "Un model de llenguatge resumeix la situació i proposa què cal fer. És una ajuda per decidir, "
                "no una decisió: es pot equivocar i no executa res.")
        plans = st.session_state.setdefault("cola_plans", {})
        if r["alert_id"] in plans:
            st.markdown(ui.llm_md(plans[r["alert_id"]]))
            st.caption(f"Redactat per IA · {llm_info} · les dades de l'alerta se li passen com a no fiables, "
                       "així que no obeeix instruccions amagades.")
        elif llm_ok:
            if st.button("Redactar el pla amb la IA", key="cola_plan_btn", icon=":material/auto_awesome:"):
                try:
                    with st.spinner("Redactant…"):
                        text = st.write_stream(data.action_plan(r))
                    plans[r["alert_id"]] = text if isinstance(text, str) else "".join(map(str, text))
                    st.rerun()
                except Exception as exc:  # pasarela caída, timeout…
                    st.error(f"No s'ha pogut redactar el pla: {exc}")
            st.caption(f"Triga uns segons · {llm_info}.")
        else:
            st.caption(f"No disponible: {llm_info} La resta del triatge funciona igual sense IA.")


changed = render_list()
order = st.session_state.get("cola_filtered") or ids
open_id = st.session_state.get("cola_open")
if open_id not in ids:  # por defecto, la primera de la bandeja (la más urgente)
    open_id = order[0] if order else ids[0]
    open_alert(open_id)
render_detail(data.get_result(open_id), scroll=changed)
