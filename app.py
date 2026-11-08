"""Punto de entrada del front (dueño: persona A). Interfaz en catalán.

    .venv\\Scripts\\python.exe -m streamlit run app.py

Datos: por defecto lee data/fixture.json (no hace falta la API). Para el back real:
    $env:SOC_MODE="live"; .venv\\Scripts\\python.exe -m streamlit run app.py

Páginas y dueños (los nombres de menú son para el público; el dueño solo se ve aquí):
  A: inici, alertes, informe_n2, accions_resposta   ·   B: triatge_directe, resum, incidents   ·   back: prototip_back
(el nombre de cada fichero es el de su página en el menú)
Fuera del menú de la demo (sigue en views/): prototip_back (primera app del back). SOC_DEV=1 la vuelve a enseñar.
Incidents ya está en el menú: los incidentes los calcula el back de verdad (incidents.py).
"""
import os

from dotenv import load_dotenv

# Lo primero: el .env (SOC_MODE, SOC_DEV…) antes de importar nada que lo lea. No pisa lo que venga del entorno.
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

import streamlit as st  # noqa: E402

from core import data, ui  # noqa: E402

st.set_page_config(page_title="Tarvia · Triatge d'alertes", page_icon=":material/shield:", layout="wide")
ui.inject_css()

DEV = os.getenv("SOC_DEV", "0") == "1"
pages = {
    "": [
        st.Page("views/inici.py", title="Inici", icon=":material/home:", default=True),
    ],
    "Revisar alertes": [
        st.Page("views/alertes.py", title="Alertes", icon=":material/inbox:"),
        st.Page("views/informe_n2.py", title="Informe per a N2", icon=":material/description:"),
        st.Page("views/incidents.py", title="Incidents", icon=":material/hub:"),
        st.Page("views/accions_resposta.py", title="Accions de resposta", icon=":material/shield:"),
    ],
    "Visió de conjunt": [
        st.Page("views/triatge_directe.py", title="Triatge en directe", icon=":material/bolt:"),
        st.Page("views/resum.py", title="Resum", icon=":material/insights:"),
    ],
}
if DEV:
    pages["Equip tècnic"] = [st.Page("views/prototip_back.py", title="Prototip del back", icon=":material/build:")]
pg = st.navigation(pages)

# Logo: solo «Tarvia SOC» (la empresa del reto), con el mismo estilo que la marca de la barra lateral
st.logo(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "tarvia_soc_logo.svg"), size="large")
with st.sidebar:
    st.markdown('<div class="brand-sub" style="margin-top:.8rem">Repte Deloitte × UAB The Hack</div>',
                unsafe_allow_html=True)
    st.caption("Mostra de 150 alertes del repte" if data.MODE == "fixture" else "Connectat a l'API del SOC")

pg.run()
