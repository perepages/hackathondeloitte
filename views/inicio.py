"""Inicio: qué es esto, cómo funciona y por dónde seguir la demo. Dueño: PERSONA A.

Pensado para alguien que no trabaja en un SOC: primero la idea en una frase, luego el flujo
en 4 pasos, las cifras y el recorrido guiado por el resto de páginas.
"""
import streamlit as st

from core import data, ui

rows = data.load_results()
n = len(rows)
esc_n = sum(r["decision"] == "escalate" for r in rows)
real = sum(r["verdict"] == "true_positive" for r in rows)
reviewed = sum(bool(r["review"]) for r in rows)

st.title("Triaje de alertas de seguridad")
st.markdown(
    '<p class="big">Las herramientas de seguridad de Tarvia lanzan <b>más de 11.000 avisos al mes</b>, y la mayoría '
    "son falsas alarmas. Este sistema revisa cada aviso como lo haría un analista: <b>comprueba los datos, explica "
    "qué ha pasado y propone qué hacer</b>. La última palabra la tiene siempre una persona.</p>",
    unsafe_allow_html=True)

st.markdown("""<div class="flow">
  <div><i>PASO 1</i><b>Llega una alerta</b><span>Una herramienta (correo, antivirus, firewall, web…) avisa de algo
  sospechoso.</span></div>
  <div><i>PASO 2</i><b>El sistema investiga</b><span>Consulta el inventario de equipos, los datos del empleado, la
  inteligencia de amenazas y los registros de actividad.</span></div>
  <div><i>PASO 3</i><b>Propone una conclusión</b><span>Ataque real, falsa alarma o actividad autorizada; cuánto
  importa y qué hacer.</span></div>
  <div><i>PASO 4</i><b>Una persona decide</b><span>El analista acepta o corrige. Ninguna acción se ejecuta sin su
  aprobación.</span></div>
</div>""", unsafe_allow_html=True)

st.write("")
m = st.columns(4)
m[0].metric("Alertas revisadas", n, help="Muestra de desarrollo que Deloitte facilita para el reto.")
m[1].metric("Se cierran sin intervención", f"{round(100 * (n - esc_n) / max(1, n))} %",
            help="El sistema concluye que no hace falta nadie más y lo deja justificado.")
m[2].metric("Necesitan a una persona", esc_n, help="Se escalan a un analista senior (nivel 2).")
m[3].metric("Ataques reales detectados", real)
if any("verdict" in r["example_fields"] for r in rows):
    st.caption("Las conclusiones de esta muestra salen de reglas de prueba mientras el motor definitivo se termina. "
               "Las comprobaciones (paso 2) sí son las reales.")
elif rows:
    by_llm = sum(r.get("decision_source") == "llm" for r in rows)
    st.caption(f"Conclusiones propuestas por la IA en {by_llm} de {n} alertas (el resto, por las reglas de "
               "respaldo), siempre con la política del SOC aplicada encima. Decide una persona.")

st.subheader("Recorrido de la demo", anchor=False)
st.caption("En este orden se entiende todo en cinco minutos.")
tour = [
    ("views/directo.py", ":material/bolt:", "1 · Triaje en directo",
     "Entran 10 alertas y se ve cómo el sistema las revisa una a una: cuáles cierra y cuáles deja a una persona."),
    ("views/cola.py", ":material/inbox:", "2 · Alertas",
     f"La bandeja del analista. Al abrir una alerta se ve qué ha pasado, qué ha comprobado el sistema y por qué "
     f"concluye lo que concluye. Aquí decide la persona ({reviewed} revisadas hasta ahora)."),
    ("views/ticket.py", ":material/description:", "3 · Informe para N2",
     "Lo que recibe el analista senior: un resumen listo para actuar, en el formato oficial de Deloitte."),
    ("views/contencion.py", ":material/shield:", "4 · Acciones de respuesta",
     "Aislar un equipo, bloquear una IP… El sistema las propone; solo se ejecutan con aprobación."),
    ("views/panel.py", ":material/insights:", "5 · Resumen",
     "Para dirección: cuánto trabajo ahorra y qué tipo de alertas llegan."),
]
for path, icon, title, text in tour:
    with st.container(border=True):
        c1, c2 = st.columns([5, 2], vertical_alignment="center")
        c1.markdown(f"**{title}**  \n<span class='muted'>{ui.esc(text)}</span>", unsafe_allow_html=True)
        c2.page_link(path, label="Abrir", icon=icon, use_container_width=True)

c1, c2 = st.columns(2, gap="large")
with c1:
    st.subheader("Qué hace el sistema y qué hace la persona", anchor=False)
    st.table({
        "El sistema": ["Lee la alerta y extrae equipos, usuarios, IPs…", "Consulta inventario, empleados, "
                       "inteligencia y registros", "Propone conclusión, gravedad y acciones", "Explica en qué se basa"],
        "La persona": ["—", "Puede revisar cada consulta y su resultado", "Acepta o corrige la propuesta",
                       "Aprueba (o no) cada acción de respuesta"],
    })
with c2:
    st.subheader("Palabras que salen en la demo", anchor=False)
    for term, meaning in ui.GLOSSARY.items():
        st.markdown(f"**{term}.** {meaning}")
    with st.expander("Las cuatro conclusiones posibles"):
        for v in ui.VERDICT_ORDER:
            st.markdown(f"{ui.verdict_badge(v)} {ui.esc(ui.VERDICT_HELP[v])}", unsafe_allow_html=True)
