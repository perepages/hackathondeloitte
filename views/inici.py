"""Inicio: qué es esto, cómo funciona y por dónde seguir la demo. Dueño: PERSONA A. Textos en catalán.

Pensado para alguien que no trabaja en un SOC: primero la idea en una frase, luego el flujo
en 4 pasos, las cifras y el recorrido guiado por el resto de páginas.
"""
import streamlit as st

from core import data, ui

rows = data.load_results()
n = len(rows)
esc_n = sum(r["decision"] == "escalate" for r in rows)
real = sum(r["verdict"] == "true_positive" for r in rows)

st.title("Triatge d'alertes de seguretat")
st.markdown(
    '<p class="big">Les eines de seguretat de Tarvia llancen <b>més d\'11.000 avisos al mes</b>, i la majoria '
    "són falses alarmes. Aquest sistema revisa cada avís com ho faria un analista: <b>comprova les dades, explica "
    "què ha passat i proposa què cal fer</b>. L'última paraula la té sempre una persona.</p>",
    unsafe_allow_html=True)

st.markdown("""<div class="flow">
  <div><i>PAS 1</i><b>Arriba una alerta</b><span>Una eina (correu, antivirus, tallafocs, web…) avisa d'alguna cosa
  sospitosa.</span></div>
  <div><i>PAS 2</i><b>El sistema investiga</b><span>Consulta l'inventari d'equips, les dades de l'empleat, la
  intel·ligència d'amenaces i els registres d'activitat.</span></div>
  <div><i>PAS 3</i><b>Proposa una conclusió</b><span>Atac real, falsa alarma o activitat autoritzada; quant
  importa i què cal fer.</span></div>
  <div><i>PAS 4</i><b>Una persona decideix</b><span>L'analista accepta o corregeix. Cap acció s'executa sense la
  seva aprovació.</span></div>
</div>""", unsafe_allow_html=True)

st.write("")
m = st.columns(4)
m[0].metric("Alertes revisades", n, help="Mostra d'alertes que Deloitte facilita per al repte.")
m[1].metric("Es tanquen sense intervenció", f"{round(100 * (n - esc_n) / max(1, n))} %",
            help="El sistema conclou que no cal ningú més i ho deixa justificat.")
m[2].metric("Necessiten una persona", esc_n, help="S'escalen a un analista sènior (nivell 2).")
m[3].metric("Atacs reals detectats", real)
if rows and not any("verdict" in r["example_fields"] for r in rows):
    st.caption("Cada conclusió la proposa la IA i la contrasten les regles dels runbooks del SOC; a sobre s'hi "
               "aplica sempre la política del SOC. Decideix una persona.")

st.subheader("Recorregut", anchor=False)
st.caption("En aquest ordre s'entén tot en cinc minuts.")
tour = [
    ("views/triatge_directe.py", ":material/bolt:", "1 · Triatge en directe",
     "Entren 10 alertes i es veu com el sistema les revisa una a una: quines tanca i quines deixa a una persona."),
    ("views/alertes.py", ":material/inbox:", "2 · Alertes",
     "La safata de l'analista. En obrir una alerta es veu què ha passat, què ha comprovat el sistema i per què "
     "conclou el que conclou. Aquí decideix la persona."),
    ("views/informe_n2.py", ":material/description:", "3 · Informe per a N2",
     "El que rep l'analista sènior: un resum a punt per actuar, en el format oficial de Deloitte."),
    ("views/accions_resposta.py", ":material/shield:", "4 · Accions de resposta",
     "Aïllar un equip, bloquejar una IP… El sistema les proposa; només s'executen amb aprovació."),
    ("views/resum.py", ":material/insights:", "5 · Resum",
     "Per a la direcció: quanta feina estalvia i quin tipus d'alertes arriben."),
]
for path, icon, title, text in tour:
    with st.container(border=True):
        c1, c2 = st.columns([5, 2], vertical_alignment="center")
        c1.markdown(f"**{title}**  \n<span class='muted'>{ui.esc(text)}</span>", unsafe_allow_html=True)
        c2.page_link(path, label="Obrir", icon=icon, use_container_width=True)

st.subheader("Què fa el sistema i què fa la persona", anchor=False)
st.table({
    "El sistema": ["Llegeix l'alerta i n'extreu equips, usuaris, IP…", "Consulta l'inventari, els empleats, "
                   "la intel·ligència i els registres", "Proposa conclusió, gravetat i accions",
                   "Explica en què es basa"],
    "La persona": ["—", "Pot revisar cada consulta i el seu resultat", "Accepta o corregeix la proposta",
                   "Aprova (o no) cada acció de resposta"],
})
with st.expander("Les quatre conclusions possibles"):
    for v in ui.VERDICT_ORDER:
        st.markdown(f"{ui.verdict_badge(v)} {ui.esc(ui.VERDICT_HELP[v])}", unsafe_allow_html=True)
