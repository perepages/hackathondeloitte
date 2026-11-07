"""Contención con aprobación humana (nivel 4).

Dueño: PERSONA A. Flujo por acción: propuesta -> aprobada (nombre + motivo) -> ejecutada.
Reglas de la política §4 visibles en pantalla:
  - block_ioc y purge_email: el N1 puede ejecutarlas sin aprobación (salvo servicios de uso dual).
  - el resto requiere aprobación de N2.
  - nada sobre la red OT: solo escalar a Operaciones.
En modo fixture la ejecución es simulada; en modo live llama a la API (/approvals y /containment).
"""
import datetime as dt

import pandas as pd
import streamlit as st

from core import data, ui

DUAL_USE = ("mega.nz", "anydesk", "teamviewer")

st.title("Acciones de respuesta")
st.markdown('<p class="muted">Cuando una alerta es un ataque real, el sistema propone cómo pararlo: aislar un equipo, '
            "bloquear una IP, borrar un correo… <b>Nada se ejecuta sin que una persona lo apruebe</b>, salvo las acciones "
            "que la política del SOC permite al nivel 1. "
            + ("En esta demo la ejecución es simulada." if data.MODE == "fixture" else "Se ejecuta contra la API del SOC.")
            + "</p>", unsafe_allow_html=True)

rows = [r for r in data.load_results()
        if r["decision"] == "escalate" and any(a["action"] not in ("close", "escalate") for a in r["recommended_actions"])]
if not rows:
    st.info("Ninguna alerta escalada tiene acciones de respuesta propuestas.")
    st.stop()

state = st.session_state.setdefault("contencion_estado", {})  # clave -> {estado, token, aprobador, motivo}
log = st.session_state.setdefault("contencion_log", [])
ids = [r["alert_id"] for r in rows]


def actions_of(view: dict) -> list[dict]:
    return [a for a in view["recommended_actions"] if a["action"] not in ("close", "escalate")]


def pending_line(view: dict) -> str:
    acts = actions_of(view)
    done = sum(state.get(f"{view['alert_id']}|{a['action']}|{a['target']}", {}).get("estado") == "ejecutada"
               for a in acts)
    return (("1 acción propuesta" if len(acts) == 1 else f"{len(acts)} acciones propuestas")
            + (f" · {done} hecha{'s' if done != 1 else ''}" if done else " · ninguna hecha"))


cur = st.session_state.get("contencion_sel") or st.session_state.get("selected_alert")
cur = cur if cur in ids else None
ui.eyebrow(f"Elige una alerta · {len(rows)} escaladas con acciones propuestas")
picked = ui.alert_cards(rows, cur or ids[0], key="contencion_pick", extra=pending_line, button_label="Ver acciones")
if picked != (cur or ids[0]):
    st.session_state["contencion_sel"] = st.session_state["selected_alert"] = picked
    st.rerun()
alert_id = picked
r = data.get_result(alert_id)
ot = ui.is_ot(r)

st.divider()
ui.eyebrow("Acciones propuestas para")
st.subheader(r["rule_name"], anchor=False)
st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.verdict_badge(r['verdict'])} &nbsp; "
            f"<span class='muted'>{ui.esc(ui.main_entity(r))}</span>", unsafe_allow_html=True)
st.markdown(f"> {ui.md(r['justification'])}")
if ot:
    st.error("El equipo está en la red de logística (OT). La política no permite al SOC tocarla: hay que avisar a Operaciones.")


def record(action: dict, result: str, who: str):
    log.append({"Hora": dt.datetime.now().strftime("%H:%M:%S"), "Alerta": alert_id,
                "Acción": ui.ACTION_LABEL.get(action["action"], action["action"]), "Objetivo": action["target"],
                "Aprobó": who, "Resultado": result})


for i, act in enumerate(actions_of(r)):
    key = f"{alert_id}|{act['action']}|{act['target']}"
    st_ = state.get(key, {"estado": "propuesta"})
    dual = any(d in str(act["target"]).lower() for d in DUAL_USE)
    needs = act["requires_approval"] or act["action"] not in data.NO_APPROVAL or dual
    with st.container(border=True):
        h1, h2 = st.columns([4, 1])
        h1.markdown(f"**{ui.ACTION_LABEL.get(act['action'], act['action'])}** · sobre `{act['target']}`")
        h2.markdown({"propuesta": "🟡 Pendiente", "aprobada": "🔵 Aprobada", "ejecutada": "🟢 Hecha"}[st_["estado"]])
        st.caption(act.get("justification", "") + (" · Necesita la aprobación de un analista senior (N2)." if needs else
                                                   " · La política permite hacerla sin aprobación."))
        if dual:
            st.caption("Es un servicio legítimo que también usan atacantes: no se bloquea para toda la empresa sin N2.")
        if ot:
            st.button("No permitido: red OT", disabled=True, key=f"contencion_ot_{i}")
        elif st_["estado"] == "ejecutada":
            st.success(f"Hecha · aprobó {st_.get('aprobador') or 'no hacía falta aprobación'}")
        elif needs and st_["estado"] == "propuesta":
            c1, c2, c3 = st.columns([2, 3, 2])
            who = c1.text_input("Quién aprueba (N2)", key=f"contencion_who_{i}")
            why = c2.text_input("Por qué", key=f"contencion_why_{i}")
            if c3.button("Aprobar", key=f"contencion_ok_{i}", disabled=not (who and why), use_container_width=True):
                token = data.approve(act["action"], act["target"], who, why)
                state[key] = {"estado": "aprobada", "token": token, "aprobador": who, "motivo": why}
                st.rerun()
        else:
            if st.button("Ejecutar", type="primary", key=f"contencion_run_{i}"):
                try:
                    res = data.contain(act["action"], act["target"], act.get("justification", ""), st_.get("token", ""))
                    state[key] = {**st_, "estado": "ejecutada"}
                    record(act, str(res.get("result", "ok")), st_.get("aprobador", "—"))
                except Exception as exc:  # p. ej. 403 de la API por falta de aprobación
                    st.error(f"La API rechazó la acción: {exc}")
                st.rerun()

st.subheader("Registro: qué se ha hecho y quién lo aprobó", anchor=False)
if log:
    st.dataframe(pd.DataFrame(log), hide_index=True, use_container_width=True)
else:
    st.caption("Todavía no se ha ejecutado ninguna acción en esta sesión.")
