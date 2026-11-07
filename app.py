"""Punto de entrada del front (dueño: persona A). Interfaz en catalán.

    .venv\\Scripts\\python.exe -m streamlit run app.py

Datos: por defecto lee data/fixture.json (no hace falta la API). Para el back real:
    $env:SOC_MODE="live"; .venv\\Scripts\\python.exe -m streamlit run app.py

Páginas y dueños (los nombres de menú son para el público; el dueño solo se ve aquí):
  A: inicio, cola, ticket, contencion   ·   B: directo, panel, incidentes   ·   back: mvp_back
Fuera del menú de la demo (siguen en views/): mvp_back (primera app del back) e incidentes (hasta que el back
agrupe alertas de verdad; hoy solo hay un incidente de ejemplo). SOC_DEV=1 los vuelve a enseñar.
"""
import os

import streamlit as st

from core import data, ui

st.set_page_config(page_title="Tarvia · Triatge d'alertes", page_icon="🛡️", layout="wide")
ui.inject_css()

DEV = os.getenv("SOC_DEV", "0") == "1"
pages = {
    "": [
        st.Page("views/inicio.py", title="Inici", icon=":material/home:", default=True),
    ],
    "Revisar alertes": [
        st.Page("views/cola.py", title="Alertes", icon=":material/inbox:"),
        st.Page("views/ticket.py", title="Informe per a N2", icon=":material/description:"),
        st.Page("views/contencion.py", title="Accions de resposta", icon=":material/shield:"),
    ],
    "Visió de conjunt": [
        st.Page("views/directo.py", title="Triatge en directe", icon=":material/bolt:"),
        st.Page("views/panel.py", title="Resum", icon=":material/insights:"),
    ],
}
if DEV:
    pages["Visió de conjunt"].append(st.Page("views/incidentes.py", title="Incidents", icon=":material/hub:"))
    pages["Equip tècnic"] = [st.Page("views/mvp_back.py", title="Prototip del back", icon=":material/build:")]
pg = st.navigation(pages)

# Logo de Deloitte (versión en blanco) tomado de la presentación oficial del reto
st.logo(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "deloitte_logo_blanco.png"), size="large")
with st.sidebar:
    st.markdown('<div class="brand">Tarvia <b>SOC</b></div>'
                '<div class="brand-sub">Triatge d\'alertes de nivell 1. El sistema proposa; una persona decideix.</div>'
                '<div class="brand-sub" style="margin-top:.8rem">Repte Deloitte × UAB The Hack</div>',
                unsafe_allow_html=True)
    st.caption("Mostra de 150 alertes del repte" if data.MODE == "fixture" else "Connectat a l'API del SOC")

pg.run()
