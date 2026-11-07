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

# ── CSS para las tarjetas con borde de severidad ──────────────────────────────
st.markdown("""<style>
.kcard{border-left:4px solid #ccc;border-radius:6px;padding:6px 10px;margin:4px 0;
       background:var(--background-color)}
.kcard-critical{border-color:#d03b3b} .kcard-high{border-color:#ec835a}
.kcard-medium{border-color:#e0a514} .kcard-low{border-color:#7f97b2}
.kcard-informational{border-color:#a7adb7} .kcard-pending{border-color:#ccc}
</style>""", unsafe_allow_html=True)


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
col_names = ["Entrantes", "Investigando", "Cerradas por el sistema", "Esperan a la persona ⚠️"]
cols = st.columns(4)
slots = []
for col, name in zip(cols, col_names):
    with col:
        st.markdown(f"**{name}**")
        slots.append(st.empty())

state = {"in": list(ids), "work": None, "calls": [], "close": [], "esc": []}


def _kcard(alert_id: str, sev: str = "pending", extra_html: str = "") -> str:
    """Tarjeta HTML con borde de color por severidad."""
    cls = f"kcard kcard-{sev}"
    inner = f"<code style='font-size:.8rem'>{alert_id}</code>"
    if extra_html:
        inner += f"<br><small>{extra_html}</small>"
    return f'<div class="{cls}">{inner}</div>'


def _queries_html(calls: list[dict]) -> str:
    parts = []
    for c in calls:
        icon = ui.QUERY_ICON.get(c.get("status", ""), "⚪")
        path = str(c.get("path", "")).replace("`", "")
        summary = ui.md(c.get("summary") or c.get("path", ""))
        parts.append(f"{icon} <code>{path}</code><br>&nbsp;&nbsp;{summary}")
    return "<br>".join(parts)


def paint():
    # Entrantes
    html_in = "".join(_kcard(i) for i in state["in"]) or "<em>—</em>"
    slots[0].markdown(html_in, unsafe_allow_html=True)

    # Investigando
    w = state["work"]
    if w:
        slots[1].markdown(_kcard(w, extra_html=_queries_html(state["calls"])), unsafe_allow_html=True)
    else:
        slots[1].markdown("<em>—</em>", unsafe_allow_html=True)

    # Cerradas
    html_close = "".join(
        _kcard(r["alert_id"], r.get("severity", "informational"),
               ui.VERDICT_LABEL.get(r["verdict"], r["verdict"]))
        for r in state["close"]
    ) or "<em>—</em>"
    slots[2].markdown(html_close, unsafe_allow_html=True)

    # Esperan a la persona
    html_esc = "".join(
        _kcard(r["alert_id"], r.get("severity", "medium"),
               ui.VERDICT_LABEL.get(r["verdict"], r["verdict"])
               + " · " + ui.SEVERITY_LABEL.get(r.get("severity", ""), r.get("severity", "")))
        for r in state["esc"]
    ) or "<em>—</em>"
    slots[3].markdown(html_esc, unsafe_allow_html=True)

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
    n_close = len(state["close"])
    n_esc = len(state["esc"])
    st.success(f"{n_close} cerradas por el sistema · {n_esc} esperan a la persona")

    # Botones «Abrir en la cola» para cada alerta escalada
    if state["esc"]:
        st.markdown("### Revisar en la cola")
        for res in state["esc"]:
            aid = res["alert_id"]
            sev_label = ui.SEVERITY_LABEL.get(res.get("severity", ""), res.get("severity", ""))
            if st.button(f"Abrir {aid} ({sev_label})", key=f"directo_open_{aid}"):
                st.session_state["selected_alert"] = aid
                st.switch_page("views/cola.py")
