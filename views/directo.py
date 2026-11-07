"""Triaje en directo: cargar las alertas sorpresa y verlas triarse (kanban).

Dueño: PERSONA B. (Las tarjetas y columnas las pinta core/ui.py: live_card / live_column.)
Pendiente B:
  - TODO B: cuando el back tenga on_event, las consultas saldrán en tiempo real (modo live).
"""
import streamlit as st

from core import data, ui

st.title("Triaje en directo")
st.markdown('<p class="muted">Así funciona con alertas nuevas, como las que dará el jurado el último día: entran en '
            "la bandeja, el sistema hace sus comprobaciones y decide. Las que no puede cerrar con seguridad "
            "<b>quedan esperando a una persona</b>.</p>", unsafe_allow_html=True)



rows = data.load_results()
by_id = {r["alert_id"]: r for r in rows}

with st.expander("Usar mis propias alertas (opcional)"):
    c1, c2 = st.columns(2)
    up = c1.file_uploader("Fichero de alertas (JSONL)", type=["jsonl", "json"], key="directo_file")
    pasted = c2.text_area("…o pega identificadores de alerta, uno por línea", key="directo_ids", height=100)
ids = data.load_alert_ids_from_jsonl(up.getvalue()) if up else [l.strip() for l in pasted.splitlines() if l.strip()]
if not ids:
    try:
        ids = data.suggest_ids(10)
    except Exception as exc:  # p. ej. la API de Deloitte no está arrancada (modo live)
        st.error(f"No he podido pedir alertas a la API del SOC: {exc}")
        ids = []
    st.caption("Sin fichero ni lista: se usarán " + str(len(ids)) + " alertas de ejemplo"
               + (" de la muestra." if data.MODE == "fixture" else " de la cola real de la API de Deloitte."))

b1, b2 = st.columns([2, 5], vertical_alignment="center")
go = b1.button(f"▶ Empezar con {len(ids)} alertas", type="primary", key="directo_go", use_container_width=True)
progress = b2.progress(0.0, text=f"0 de {len(ids)} alertas revisadas")
board = st.empty()

state = {"in": list(ids), "work": None, "calls": [], "close": [], "esc": []}


def placeholder(alert_id: str) -> dict:
    return by_id.get(alert_id) or data.alert_brief(alert_id) or {"rule_name": alert_id, "source_product": "",
                                                                  "created_at": ""}


def paint():
    cols = board.columns(4)
    work = [ui.live_card(placeholder(state["work"]), "work", state["calls"])] if state["work"] else []
    spec = [
        ("Entran", "Avisos nuevos esperando revisión", [ui.live_card(placeholder(i), "in") for i in state["in"]], False),
        ("Investigando", "El sistema está haciendo comprobaciones", work, False),
        ("Cerradas por el sistema", "Concluidas y justificadas", [ui.live_card(r, "close") for r in state["close"]], False),
        ("Esperan a una persona", "Se escalan a un analista senior", [ui.live_card(r, "esc") for r in state["esc"]], True),
    ]
    for col, (title, hint, cards, human) in zip(cols, spec):
        col.markdown(ui.live_column(title, hint, cards, human), unsafe_allow_html=True)
    done = len(state["close"]) + len(state["esc"])
    progress.progress(done / max(1, len(ids)), text=f"{done} de {len(ids)} alertas revisadas")


def on_event(ev: dict):
    if ev["type"] == "alert_started":
        if ev["alert_id"] in state["in"]:
            state["in"].remove(ev["alert_id"])
        state["work"], state["calls"] = ev["alert_id"], []
    elif ev["type"] == "api_call":
        state["calls"].append(ev)
    elif ev["type"] == "verdict":
        res = ev["result"]; state["work"] = None
        state["esc" if res["decision"] == "escalate" else "close"].append(res)
    paint()


paint()
if go:
    data.run_triage(ids, on_event)
    st.session_state["directo_ultimo"] = [r["alert_id"] for r in state["esc"]]
    st.success(f"Listo: {len(state['close'])} cerradas por el sistema y {len(state['esc'])} esperan a una persona.")

pending = st.session_state.get("directo_ultimo") or []
if pending:
    st.markdown("**Abrir las que esperan a una persona:**")
    for i, alert_id in enumerate(pending):
        if st.button(placeholder(alert_id)["rule_name"], key=f"directo_open_{i}", icon=":material/open_in_new:"):
            st.session_state["selected_alert"] = alert_id
            st.switch_page("views/cola.py")
