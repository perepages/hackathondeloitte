"""Punto de entrada del front (dueño: persona A).

    .venv\\Scripts\\python.exe -m streamlit run app.py

Datos: por defecto lee data/fixture.json (no hace falta la API). Para el back real:
    $env:SOC_MODE="live"; .venv\\Scripts\\python.exe -m streamlit run app.py
"""
import streamlit as st

from core import data, ui

st.set_page_config(page_title="Tarvia · Triaje N1", page_icon="🛡️", layout="wide")
ui.inject_css()

pages = {
    "Analista · persona A": [
        st.Page("views/cola.py", title="Cola de triaje", icon="📥", default=True),
        st.Page("views/ticket.py", title="Ticket para N2", icon="🧾"),
        st.Page("views/contencion.py", title="Contención", icon="🛑"),
    ],
    "Operación · persona B": [
        st.Page("views/directo.py", title="En directo", icon="⚡"),
        st.Page("views/panel.py", title="Panel", icon="📊"),
        st.Page("views/incidentes.py", title="Incidentes", icon="🧩"),
    ],
    "Referencia": [
        st.Page("views/mvp_back.py", title="MVP del back", icon="🔧"),
    ],
}
pg = st.navigation(pages)

with st.sidebar:
    st.caption(f"Datos: **{data.MODE}**" + (" · con campos de ejemplo marcados" if data.USE_EXAMPLES else ""))

pg.run()
