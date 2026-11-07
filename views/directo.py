"""Triaje en directo: cargar las alertas sorpresa y verlas triarse (kanban). Textos en catalán.

Dueño: PERSONA B. (Las tarjetas y columnas las pinta core/ui.py: live_card / live_column.)
Pendiente B:
  - TODO B: cuando el back tenga on_event, las consultas saldrán en tiempo real (modo live).
"""
import streamlit as st
import streamlit.components.v1 as components

from core import data, ui

st.title("Triatge en directe")
st.markdown('<p class="muted">Així funciona amb alertes noves: entren a la safata, el sistema fa les seves '
            "comprovacions i decideix. Les que no pot tancar amb seguretat <b>queden esperant una persona</b>.</p>",
            unsafe_allow_html=True)


rows = data.load_results()
by_id = {r["alert_id"]: r for r in rows}

with st.expander("Fer servir les meves alertes (opcional)"):
    c1, c2 = st.columns(2)
    up = c1.file_uploader("Fitxer d'alertes (JSONL)", type=["jsonl", "json"], key="directo_file")
    pasted = c2.text_area("…o enganxa identificadors d'alerta, un per línia", key="directo_ids", height=100)
ids = data.load_alert_ids_from_jsonl(up.getvalue()) if up else [l.strip() for l in pasted.splitlines() if l.strip()]
if not ids:
    try:
        ids = data.suggest_ids(10)
    except Exception as exc:  # p. ej. la API de Deloitte no está arrancada (modo live)
        st.error(f"No he pogut demanar alertes a l'API del SOC: {exc}")
        ids = []
    st.caption(f"Sense fitxer ni llista: es faran servir {len(ids)} alertes d'exemple"
               + (" de la mostra." if data.MODE == "fixture" else " de la cua real de l'API de Deloitte."))

b1, b2 = st.columns([2, 5], vertical_alignment="center")
go = b1.button(f"▶ Començar amb {len(ids)} alertes", type="primary", key="directo_go", use_container_width=True)
progress = b2.progress(0.0, text=f"0 de {len(ids)} alertes revisades")
board = st.empty()

state = {"in": list(ids), "work": None, "calls": [], "close": [], "esc": []}


def placeholder(alert_id: str) -> dict:
    return by_id.get(alert_id) or data.alert_brief(alert_id) or {"rule_name": alert_id, "source_product": "",
                                                                  "created_at": ""}


BOARD_H = 420  # altura fija de cada columna del kanban; scroll interno si hay muchas tarjetas


def paint():
    work = [ui.live_card(placeholder(state["work"]), "work", state["calls"])] if state["work"] else []
    spec = [
        ("Entren", "Avisos nous esperant revisió", [ui.live_card(placeholder(i), "in") for i in state["in"]], False),
        ("Investigant", "El sistema està fent comprovacions", work, False),
        ("Tancades pel sistema", "Concloses i justificades", [ui.live_card(r, "close") for r in state["close"]], False),
        ("Esperen una persona", "S'escalen a un analista sènior", [ui.live_card(r, "esc") for r in state["esc"]], True),
    ]
    html = (
        '<div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem">'
        + "".join(ui.live_column(t, h, c, hum, max_height=BOARD_H) for t, h, c, hum in spec)
        + "</div>"
    )
    board.markdown(html, unsafe_allow_html=True)
    done = len(state["close"]) + len(state["esc"])
    progress.progress(done / max(1, len(ids)), text=f"{done} de {len(ids)} alertes revisades")


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
    esc_ids = [r["alert_id"] for r in state["esc"]]
    st.session_state["directo_ultimo"] = esc_ids
    if esc_ids:
        components.html(
            "<script>window.parent.document.getElementById('escaladas')"
            ".scrollIntoView({behavior:'smooth',block:'start'});</script>",
            height=0,
        )

pending = st.session_state.get("directo_ultimo") or []
if pending:
    st.markdown('<div id="escaladas"></div>', unsafe_allow_html=True)
    st.divider()
    st.markdown("#### Alertes que esperen una persona")
    st.caption("Prem una targeta per obrir-la a la safata d'alertes.")
    cols = st.columns(min(len(pending), 4))
    for i, alert_id in enumerate(pending):
        p = placeholder(alert_id)
        sev = p.get("severity", "medium")
        with cols[i % len(cols)].container(border=True):
            st.markdown(ui.severity_badge(sev), unsafe_allow_html=True)
            st.markdown(f"**{ui.md(p.get('rule_name', alert_id))}**")
            st.caption(p.get("source_product", "") + (" · " if p.get("source_product") else "") + alert_id)
            if st.button("Obrir", key=f"directo_open_{i}", use_container_width=True,
                         type="primary", icon=":material/open_in_new:"):
                st.session_state["selected_alert"] = st.session_state["cola_open"] = alert_id
                st.switch_page("views/cola.py")
