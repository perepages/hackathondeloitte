"""Triaje en directo: cargar las alertas sorpresa y verlas triarse (kanban).

Dueño: PERSONA B. Punto de partida que ya funciona: carga IDs, llama a data.run_triage y
mueve las tarjetas por 4 columnas a medida que llegan los eventos.
Pendiente (ver el plan de frontend):
  - TODO B: diseño de las tarjetas (borde por severidad, veredicto, consultas apareciendo).
  - TODO B: al acabar, botón «Abrir en la cola» por cada alerta que espera a la persona.
  - TODO B: cuando el back tenga on_event, las consultas saldrán en tiempo real (modo live).
"""
import streamlit as st

from core import data, ui

st.title("Triaje en directo")
st.caption("Así verá el jurado las alertas sorpresa: entran, el sistema consulta la API y decide, "
           "y lo que se escala queda esperando a la persona.")


def sample_ids(rows: list[dict]) -> list[str]:
    """10 de ejemplo: 5 que se cierran y 5 que se escalan, de reglas distintas."""
    seen, pick = set(), []
    for want in ("close", "escalate"):
        n = 0
        for r in rows:
            if r["decision"] == want and r["rule_id"] not in seen and n < 5:
                seen.add(r["rule_id"]); pick.append(r["alert_id"]); n += 1
    return pick


rows = data.load_results()
c1, c2 = st.columns(2)
up = c1.file_uploader("JSONL de alertas", type=["jsonl", "json"], key="directo_file")
pasted = c2.text_area("…o pega IDs (uno por línea)", key="directo_ids", height=100)
ids = data.load_alert_ids_from_jsonl(up.getvalue()) if up else [l.strip() for l in pasted.splitlines() if l.strip()]
if not ids:
    ids = sample_ids(rows)
    st.caption(f"Sin entrada: se usarán {len(ids)} alertas de ejemplo.")

go = st.button(f"▶ Iniciar triaje de {len(ids)} alertas", type="primary", key="directo_go")
progress = st.progress(0.0, text=f"0 de {len(ids)} alertas triadas")
names = ["Entrantes", "Investigando", "Cerradas por el sistema", "Esperan a la persona"]
cols = st.columns(4)
slots = []
for col, name in zip(cols, names):
    with col:
        st.markdown(f"**{name}**")
        slots.append(st.empty())

state = {"in": list(ids), "work": None, "calls": [], "close": [], "esc": []}


def card(alert_id: str, extra: str = "") -> str:
    return f"`{alert_id}`" + (f"  \n{extra}" if extra else "")


def paint():
    slots[0].markdown("\n\n".join(card(i) for i in state["in"]) or "—")
    w = state["work"]
    slots[1].markdown(card(w, "  \n".join(f"{ui.QUERY_ICON.get(c['status'], '⚪')} {ui.md(c['path'])}" for c in state["calls"]))
                      if w else "—")
    slots[2].markdown("\n\n".join(card(r["alert_id"], ui.VERDICT_LABEL[r["verdict"]]) for r in state["close"]) or "—")
    slots[3].markdown("\n\n".join(card(r["alert_id"], ui.VERDICT_LABEL[r["verdict"]] + " · " + ui.SEVERITY_LABEL[r["severity"]])
                                  for r in state["esc"]) or "—")
    done = len(state["close"]) + len(state["esc"])
    progress.progress(done / max(1, len(ids)), text=f"{done} de {len(ids)} alertas triadas")


def on_event(ev: dict):
    if ev["type"] == "alert_started":
        state["in"].remove(ev["alert_id"]); state["work"], state["calls"] = ev["alert_id"], []
    elif ev["type"] == "api_call":
        state["calls"].append(ev)
    elif ev["type"] == "verdict":
        res = ev["result"]; state["work"] = None
        state["esc" if res["decision"] == "escalate" else "close"].append(res)
    paint()


paint()
if go:
    data.run_triage(ids, on_event)
    st.success(f"{len(state['close'])} cerradas por el sistema · {len(state['esc'])} esperan a la persona")
