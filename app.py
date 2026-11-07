"""Punto de entrada del front (dueño: persona A).

    .venv\\Scripts\\python.exe -m streamlit run app.py

Datos: por defecto lee data/fixture.json (no hace falta la API). Para el back real:
    $env:SOC_MODE="live"; .venv\\Scripts\\python.exe -m streamlit run app.py

Páginas y dueños (los nombres de menú son para el público; el dueño solo se ve aquí):
  A: inicio, cola, ticket, contencion   ·   B: directo, panel, incidentes   ·   back: mvp_back
"""
import streamlit as st

from core import data, ui

st.set_page_config(page_title="Tarvia · Triaje de alertas", page_icon="🛡️", layout="wide")
ui.inject_css()

pages = {
    "": [
        st.Page("views/inicio.py", title="Inicio", icon=":material/home:", default=True),
    ],
    "Revisar alertas": [
        st.Page("views/cola.py", title="Alertas", icon=":material/inbox:"),
        st.Page("views/ticket.py", title="Informe para N2", icon=":material/description:"),
        st.Page("views/contencion.py", title="Acciones de respuesta", icon=":material/shield:"),
    ],
    "Visión de conjunto": [
        st.Page("views/directo.py", title="Triaje en directo", icon=":material/bolt:"),
        st.Page("views/panel.py", title="Resumen", icon=":material/insights:"),
        st.Page("views/incidentes.py", title="Incidentes", icon=":material/hub:"),
    ],
    "Equipo técnico": [
        st.Page("views/mvp_back.py", title="Prototipo del back", icon=":material/build:"),
    ],
}
pg = st.navigation(pages)

with st.sidebar:
    st.caption("**Tarvia · SOC** — triaje de nivel 1 asistido. El sistema propone; una persona decide.")
    st.caption(("Datos de la muestra de desarrollo (sin conexión)" if data.MODE == "fixture"
                else "Conectado a la API del SOC") + (" · con valores de ejemplo marcados" if data.USE_EXAMPLES else ""))

pg.run()
