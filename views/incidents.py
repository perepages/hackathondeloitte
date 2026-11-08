"""Incidents (nivel 2): alertas DISTINTAS de la misma intrusión, en un único ticket (política del SOC §5 y §6).

La agrupación la hace el back (incidents.py) al cargar los resultados. Esta página explica cada incidente: por qué se han
juntado sus alertas (las pistas compartidas), por qué se escala, en qué orden pasó (línea temporal MITRE, de Adri) y
lleva al informe para N2, que es uno por incidente.
"""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from core import data, ui

TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Collection", "Command and Control", "Exfiltration", "Impact", "Desconeguda"]

st.title("Incidents")
st.markdown('<p class="muted">Un incident junta alertes <b>diferents</b> que formen part del mateix atac, encara que '
            "passin dies entre elles: el mateix atacant (IP, domini, remitent, fitxer), el mateix compte o el mateix "
            "equip. Així l'analista sènior rep <b>un sol informe</b> per atac i es veuen cadenes que alerta per alerta "
            "semblarien poca cosa (política del SOC §5 i §6).</p>", unsafe_allow_html=True)

rows = data.load_results()
if not rows:
    ui.empty_state("incidents")
incs = data.load_incidents()
if not incs:
    st.info("No hi ha alertes d'atac que comparteixin pistes: cap incident.", icon=":material/info:")
    st.stop()

in_inc = sum(i["count"] for i in incs)
m = st.columns(4)
m[0].metric("Incidents", len(incs))
m[1].metric("Alertes", in_inc, help="Alertes que formen part d'algun incident (comptant les repeticions)")
m[2].metric("Informes estalviats", in_inc - len(incs),
            help="Sense agrupar, cada alerta seria un informe per al N2; agrupades, un per incident")
m[3].metric("Cadenes", sum(1 for i in incs if i["chain"]),
            help="Dues o més regles diferents amb conclusió d'atac: s'escalen sempre (política §5)")

with st.expander("Com s'agrupen les alertes"):
    st.markdown(
        "- **Pista d'atacant** (IP externa, domini, fitxer, remitent, correu, sessió de l'assistent): uneix alertes de "
        "tot el període.\n"
        "- **Mateix compte**: alertes a menys de 14 dies l'una de l'altra.\n"
        "- **Mateix equip**: alertes a menys de 48 hores (la política demana correlacionar ±24 h).\n"
        "- **No uneixen**: la gravetat, la criticitat ni el tipus d'alerta; els dominis propis i els serveis "
        "legítims; i les pistes massa populars (un servidor de salt o un remitent de butlletins).\n"
        "- **Només entren** les alertes d'atac, amb dades que falten o escalades: l'activitat autoritzada no fa "
        "incidents.\n"
        "- **S'escala** si alguna alerta ja s'escalava o si és una cadena (dues o més regles diferents d'atac).")


def _timeline(members: list[dict]) -> None:
    df = pd.DataFrame([{"Hora": r["created_at"][:19], "Alerta": r["alert_id"], "Què": r["rule_name"],
                        "Fase": (r["alert"].get("mitre") or {}).get("tactic") or "Desconeguda",
                        "Tècnica": (r["alert"].get("mitre") or {}).get("technique") or "",
                        "Gravetat": ui.SEVERITY_LABEL.get(r["severity"], r["severity"])} for r in members])
    chart = (alt.Chart(df).mark_circle(size=140)
             .encode(x=alt.X("Hora:T", title=None),
                     y=alt.Y("Fase:N", sort=TACTICS, title=None, axis=alt.Axis(labelLimit=170)),
                     color=alt.Color("Fase:N", legend=None),
                     tooltip=["Hora", "Alerta", "Què", "Fase", "Tècnica", "Gravetat"])
             .properties(height=max(150, df["Fase"].nunique() * 50),
                         title="Fases de l'atac (MITRE) al llarg del temps"))
    st.altair_chart(chart, use_container_width=True)


def _value(clue: dict) -> str:
    v = clue["value"].replace("`", "")
    if clue["kind"] == "equip" and not v.replace(".", "").isdigit():
        v = v.upper()
    return v[:16] + "…" if clue["kind"] == "hash" else v[:60]


focus = st.session_state.pop("focus_incident", None)
for inc in incs:
    _, members = data.get_incident(inc["incident_id"])
    with st.container(border=True):
        st.markdown(f"{ui.severity_badge(inc['severity'])} &nbsp; {ui.decision_badge(inc['decision'])} &nbsp; "
                    f"<span class='muted'>{ui.esc(inc['incident_id'])} · {ui.fmt_time(inc['first_seen'])} → "
                    f"{ui.fmt_time(inc['last_seen'])}</span>", unsafe_allow_html=True)
        st.subheader(inc["title"], anchor=False)
        clues = " · ".join(f"**{ui.md(s['label'])}** `{_value(s)}`" for s in inc["shared"][:8])
        st.markdown(f"**Per què són el mateix atac:** comparteixen {clues}"
                    + (f" i {len(inc['shared']) - 8} pistes més" if len(inc["shared"]) > 8 else "") + ".")
        if inc["reasons"]:
            st.markdown("**Per què s'escala:** " + "; ".join(ui.md(x) for x in inc["reasons"]) + ".")
        with st.expander(f"Les {inc['count']} alertes i la línia temporal", expanded=focus == inc["incident_id"]):
            st.dataframe(pd.DataFrame([{
                "Hora": ui.fmt_time(r["created_at"]), "Alerta": r["alert_id"], "Què ha detectat": r["rule_name"],
                "Conclusió": ui.VERDICT_LABEL[r["verdict"]],
                "Gravetat": ui.SEVERITY_LABEL.get(r["severity"], r["severity"]),
                "Proposta": ui.DECISION_LABEL[r["decision"]]
                + (" (per l'incident)" if r.get("escalated_by_incident") else ""),
                "Repeticions": ui.group_count(r)} for r in members]), hide_index=True, use_container_width=True)
            _timeline(members)
        if st.button("Veure l'informe per a N2 d'aquest incident", key=f"inc_{inc['incident_id']}",
                     icon=":material/description:"):
            st.session_state["selected_alert"] = members[0]["alert_id"]
            st.switch_page("views/informe_n2.py")
