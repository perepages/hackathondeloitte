"""Contención con aprobación humana (nivel 4). Textos en catalán.

Dueño: PERSONA A. Una lista: cada alerta escalada con acciones propuestas es una fila (desplegable) y, al abrirla,
salen debajo sus acciones. Flujo por acción: propuesta -> aprobada (nombre + motivo) -> ejecutada.
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
STATUS_LABEL = {"propuesta": "🟡 Pendent", "aprobada": "🔵 Aprovada", "ejecutada": "🟢 Feta"}

st.title("Accions de resposta")
st.markdown('<p class="muted">Quan una alerta és un atac real, el sistema proposa com aturar-lo: aïllar un equip, '
            "bloquejar una IP, esborrar un correu… <b>No s'executa res sense que una persona ho aprovi</b>, excepte "
            "les accions que la política del SOC permet al nivell 1. "
            + ("En aquesta demo l'execució és simulada." if data.MODE == "fixture" else "S'executa contra l'API del SOC.")
            + "</p>", unsafe_allow_html=True)

rows = [r for r in data.load_results()
        if r["decision"] == "escalate" and any(a["action"] not in ("close", "escalate") for a in r["recommended_actions"])]
if not rows:
    st.info("Cap alerta escalada té accions de resposta proposades.")
    st.stop()

state = st.session_state.setdefault("contencion_estado", {})  # clave -> {estado, token, aprobador, motivo}
log = st.session_state.setdefault("contencion_log", [])
SEV_RANK = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "informational"])}
rows = sorted(rows, key=lambda v: (SEV_RANK.get(v["severity"], 9), v["created_at"]))  # de més a menys greu


def actions_of(view: dict) -> list[dict]:
    return [a for a in view["recommended_actions"] if a["action"] not in ("close", "escalate")]


def akey(view: dict, act: dict) -> str:
    return f"{view['alert_id']}|{act['action']}|{act['target']}"


def pending_line(view: dict) -> str:
    acts = actions_of(view)
    done = sum(state.get(akey(view, a), {}).get("estado") == "ejecutada" for a in acts)
    return (("1 acció proposada" if len(acts) == 1 else f"{len(acts)} accions proposades")
            + (f" · {done} feta{'s' if done != 1 else ''}" if done else " · cap de feta"))


def record(view: dict, action: dict, result: str, who: str):
    log.append({"Hora": dt.datetime.now().strftime("%H:%M:%S"), "Alerta": view["alert_id"],
                "Acció": ui.ACTION_LABEL.get(action["action"], action["action"]), "Objectiu": action["target"],
                "Ho va aprovar": who, "Resultat": result})


def render_actions(view: dict, j: int) -> None:
    """Les accions d'una alerta, dins del seu desplegable."""
    ot = ui.is_ot(view)
    st.markdown(f"{ui.severity_badge(view['severity'])} &nbsp; {ui.verdict_badge(view['verdict'])} &nbsp; "
                f"<span class='muted'>{ui.esc(view['alert_id'])}</span>", unsafe_allow_html=True)
    st.markdown(f"> {ui.md(view['justification'])}")
    if ot:
        st.error("L'equip és a la xarxa de logística (OT). La política no permet al SOC tocar-la: cal avisar Operacions.")
    for i, act in enumerate(actions_of(view)):
        key = akey(view, act)
        st_ = state.get(key, {"estado": "propuesta"})
        dual = any(d in str(act["target"]).lower() for d in DUAL_USE)
        needs = act["requires_approval"] or act["action"] not in data.NO_APPROVAL or dual
        with st.container(border=True):
            h1, h2 = st.columns([4, 1])
            h1.markdown(f"**{ui.ACTION_LABEL.get(act['action'], act['action'])}** · sobre `{act['target']}`")
            h2.markdown(STATUS_LABEL[st_["estado"]])
            st.caption(act.get("justification", "") + (" · Necessita l'aprovació d'un analista sènior (N2)." if needs
                                                       else " · La política permet fer-la sense aprovació."))
            if dual:
                st.caption("És un servei legítim que també fan servir els atacants: no es bloqueja per a tota l'empresa "
                           "sense N2.")
            if ot:
                st.button("No permès: xarxa OT", disabled=True, key=f"contencion_ot_{j}_{i}")
            elif st_["estado"] == "ejecutada":
                st.success(f"Feta · ho va aprovar {st_.get('aprobador') or 'ningú (no calia aprovació)'}")
            elif needs and st_["estado"] == "propuesta":
                c1, c2, c3 = st.columns([2, 3, 2], vertical_alignment="bottom")
                who = c1.text_input("Qui ho aprova (N2)", key=f"contencion_who_{j}_{i}")
                why = c2.text_input("Per què", key=f"contencion_why_{j}_{i}")
                if c3.button("Aprovar", key=f"contencion_ok_{j}_{i}", disabled=not (who and why),
                             use_container_width=True):
                    token = data.approve(act["action"], act["target"], who, why)
                    state[key] = {"estado": "aprobada", "token": token, "aprobador": who, "motivo": why}
                    st.session_state["contencion_sel"] = view["alert_id"]
                    st.rerun()
            else:
                if st.button("Executar", type="primary", key=f"contencion_run_{j}_{i}"):
                    try:
                        res = data.contain(act["action"], act["target"], act.get("justification", ""),
                                           st_.get("token", ""))
                        state[key] = {**st_, "estado": "ejecutada"}
                        record(view, act, str(res.get("result", "ok")), st_.get("aprobador", "—"))
                    except Exception as exc:  # p. ej. 403 de la API por falta de aprobación
                        st.error(f"L'API ha rebutjat l'acció: {exc}")
                    st.session_state["contencion_sel"] = view["alert_id"]
                    st.rerun()


# ---------------------------------------------------------------------------- llista
open_id = st.session_state.get("contencion_sel") or st.session_state.get("selected_alert")
ui.eyebrow(f"{len(rows)} alertes escalades amb accions proposades · obre'n una per veure-les")
for j, r in enumerate(rows):
    entity = ui.main_entity(r).replace("@", "@​")  # que el correu no es converteixi en enllaç
    label = (f"{ui.SEVERITY_DOT.get(r['severity'], '⚪')} **{ui.SEVERITY_LABEL[r['severity']].capitalize()}** · "
             f"{ui.md(r['rule_name'])}"
             + (f" · {ui.md(entity)}" if entity else "")
             + f" · {ui.fmt_time(r['created_at'])[5:16]} · _{pending_line(r)}_")
    with st.expander(label, expanded=r["alert_id"] == open_id):
        render_actions(r, j)

st.subheader("Registre: què s'ha fet i qui ho va aprovar", anchor=False)
if log:
    st.dataframe(pd.DataFrame(log), hide_index=True, use_container_width=True)
else:
    st.caption("Encara no s'ha executat cap acció en aquesta sessió.")
