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

st.title("Contención")
st.caption("El sistema propone; una persona aprueba; solo entonces se ejecuta. "
           + ("Ejecución simulada (modo fixture)." if data.MODE == "fixture" else "Ejecución contra la API simulada."))

rows = [r for r in data.load_results()
        if r["decision"] == "escalate" and any(a["action"] not in ("close", "escalate") for a in r["recommended_actions"])]
if not rows:
    st.info("Ninguna alerta escalada tiene acciones de contención propuestas.")
    st.stop()

state = st.session_state.setdefault("contencion_estado", {})  # clave -> {estado, token, aprobador, motivo}
log = st.session_state.setdefault("contencion_log", [])
ids = [r["alert_id"] for r in rows]
cur = st.session_state.get("selected_alert")
alert_id = st.selectbox("Alerta escalada", ids, index=ids.index(cur) if cur in ids else 0, key="contencion_alert",
                        format_func=lambda i: f"{i} · {data.get_result(i)['rule_name']}")
r = data.get_result(alert_id)
ot = ui.is_ot(r)
st.markdown(f"{ui.severity_badge(r['severity'])} &nbsp; {ui.verdict_badge(r['verdict'])} &nbsp; "
            f"<small>{ui.md(r['justification'])}</small>", unsafe_allow_html=True)
if ot:
    st.error("Activo en la red OT (LOGISTICS-OT). La política no permite al SOC actuar: **escalar a Operaciones**.")


def record(action: dict, result: str, who: str):
    log.append({"Hora": dt.datetime.now().strftime("%H:%M:%S"), "Alerta": alert_id,
                "Acción": ui.ACTION_LABEL.get(action["action"], action["action"]), "Objetivo": action["target"],
                "Aprobó": who, "Resultado": result})


for i, act in enumerate(a for a in r["recommended_actions"] if a["action"] not in ("close", "escalate")):
    key = f"{alert_id}|{act['action']}|{act['target']}"
    st_ = state.get(key, {"estado": "propuesta"})
    dual = any(d in str(act["target"]).lower() for d in DUAL_USE)
    needs = act["requires_approval"] or act["action"] not in data.NO_APPROVAL or dual
    with st.container(border=True):
        h1, h2 = st.columns([4, 1])
        h1.markdown(f"**{ui.ACTION_LABEL.get(act['action'], act['action'])}** · `{ui.md(act['target'])}`")
        h2.markdown({"propuesta": "🟡 propuesta", "aprobada": "🔵 aprobada", "ejecutada": "🟢 ejecutada"}[st_["estado"]])
        st.caption(act.get("justification", "") + (" · Requiere aprobación de N2." if needs else
                                                   " · El N1 puede ejecutarla sin aprobación (política §4)."))
        if dual:
            st.caption("Servicio de uso dual: no se bloquea a nivel global sin N2.")
        if ot:
            st.button("Bloqueada: red OT", disabled=True, key=f"contencion_ot_{i}")
        elif st_["estado"] == "ejecutada":
            st.success(f"Ejecutada · aprobó {st_.get('aprobador') or 'no hacía falta'}")
        elif needs and st_["estado"] == "propuesta":
            c1, c2, c3 = st.columns([2, 3, 2])
            who = c1.text_input("Aprobador (N2)", key=f"contencion_who_{i}")
            why = c2.text_input("Motivo", key=f"contencion_why_{i}")
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

st.subheader("Registro de acciones", anchor=False)
if log:
    st.dataframe(pd.DataFrame(log), hide_index=True, use_container_width=True)
else:
    st.caption("Todavía no se ha ejecutado ninguna acción en esta sesión.")
