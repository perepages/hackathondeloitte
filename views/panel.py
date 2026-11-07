"""Panel de negocio + SLA.

Dueño: PERSONA B. Punto de partida: métricas y un gráfico. Colores SIEMPRE de core/ui.py.
Pendiente (ver la maqueta demo/triaje_demo.html, vista Panel):
  - TODO B: severidad de la regla frente a severidad final (mapa de calor).
  - TODO B: alertas por día, apiladas por decisión.
  - TODO B: SLA de las escaladas con @st.fragment(run_every="10s").
"""
import altair as alt
import pandas as pd
import streamlit as st

from core import data, ui

MIN_PER_ALERT = 8  # supuesto: minutos de un analista N1 por alerta triada a mano

st.title("Panel")
rows = data.load_results()
n = len(rows)
closed = sum(r["decision"] == "close" for r in rows)
m = st.columns(4)
m[0].metric("Alertas triadas", n)
m[1].metric("Cerradas por el sistema", f"{round(100 * closed / max(1, n))} %")
m[2].metric("Escaladas a N2", n - closed)
m[3].metric("Horas de analista ahorradas", f"{closed * MIN_PER_ALERT / 60:.1f} h",
            help=f"Supuesto: {MIN_PER_ALERT} min por alerta triada a mano")

if any("verdict" in r["example_fields"] for r in rows):
    st.caption("Los veredictos y decisiones son de ejemplo (reglas de prueba) hasta que el back los genere.")

st.subheader("Veredicto por regla de detección")
df = pd.DataFrame([{"Regla": r["rule_name"], "Veredicto": ui.VERDICT_LABEL[r["verdict"]]} for r in rows])
chart = alt.Chart(df).mark_bar().encode(
    y=alt.Y("Regla:N", sort="-x", title=None),
    x=alt.X("count():Q", title="Alertas"),
    color=alt.Color("Veredicto:N", scale=alt.Scale(domain=[ui.VERDICT_LABEL[v] for v in ui.VERDICT_ORDER],
                                                    range=[ui.VERDICT_COLOR[v] for v in ui.VERDICT_ORDER]),
                    legend=alt.Legend(orient="top", title=None)),
    tooltip=["Regla", "Veredicto", "count()"],
)
st.altair_chart(chart, use_container_width=True)
