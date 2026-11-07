"""Panel de negocio + SLA.

Dueño: PERSONA B. Punto de partida: métricas y un gráfico. Colores SIEMPRE de core/ui.py.
Pendiente (ver la maqueta demo/triaje_demo.html, vista Panel):
  - TODO B: severidad de la regla frente a severidad final (mapa de calor).
  - TODO B: alertas por día, apiladas por decisión.
  - TODO B: SLA de las escaladas con @st.fragment(run_every="10s").
"""
import datetime as dt

import altair as alt
import pandas as pd
import streamlit as st

from core import data, ui

MIN_PER_ALERT = 8  # supuesto: minutos de un analista N1 por alerta triada a mano

# SLA por severidad (en minutos)
SLA_MIN = {"critical": 15, "high": 30, "medium": 240, "low": 1440, "informational": 1440}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

st.title("Panel")
rows = data.load_results()
n = len(rows)
closed = sum(r["decision"] == "close" for r in rows)
m = st.columns(4)
m[0].metric("Alertas triadas", n)
m[1].metric("Cerradas por el sistema", f"{round(100 * closed / max(1, n))} %")
m[2].metric("Escaladas a N2", n - closed)
m[3].metric("Horas de analista ahorradas", f"{closed * MIN_PER_ALERT / 60:.1f} h",
            help=f"Supuesto: {MIN_PER_ALERT} min por alerta triada a mano. "
                 f"Solo las {closed} cerradas automáticamente evitan la revisión manual.")

if any("verdict" in r["example_fields"] for r in rows):
    st.caption("Los veredictos y decisiones son de ejemplo (reglas de prueba) hasta que el back los genere.")

# ── Reparto por veredicto (barra al 100 %) ────────────────────────────────────
st.subheader("Reparto por veredicto")
df_verd = pd.DataFrame([{"Veredicto": ui.VERDICT_LABEL[r["verdict"]]} for r in rows])
df_verd["n"] = 1
df_verd_agg = df_verd.groupby("Veredicto", as_index=False)["n"].sum()
df_verd_agg["pct"] = df_verd_agg["n"] / df_verd_agg["n"].sum() * 100
bar100 = (
    alt.Chart(df_verd_agg)
    .mark_bar()
    .encode(
        x=alt.X("pct:Q", title="% alertas", stack="normalize",
                axis=alt.Axis(format=".0%", labels=False, ticks=False, grid=False)),
        color=alt.Color(
            "Veredicto:N",
            scale=alt.Scale(
                domain=[ui.VERDICT_LABEL[v] for v in ui.VERDICT_ORDER],
                range=[ui.VERDICT_COLOR[v] for v in ui.VERDICT_ORDER],
            ),
            legend=alt.Legend(orient="right", title=None),
        ),
        tooltip=["Veredicto", "n", alt.Tooltip("pct:Q", format=".1f", title="%")],
    )
    .properties(height=50)
)
st.altair_chart(bar100, use_container_width=True)

# ── Veredicto por regla (barras horizontales apiladas) ────────────────────────
st.subheader("Veredicto por regla de detección")
df_rule = pd.DataFrame([{"Regla": r["rule_name"], "Veredicto": ui.VERDICT_LABEL[r["verdict"]]} for r in rows])
top_rules = df_rule["Regla"].value_counts().head(9).index.tolist()
df_rule["Regla"] = df_rule["Regla"].where(df_rule["Regla"].isin(top_rules), "Otras")
chart_rule = (
    alt.Chart(df_rule)
    .mark_bar()
    .encode(
        y=alt.Y("Regla:N", sort="-x", title=None),
        x=alt.X("count():Q", title="Alertas"),
        color=alt.Color(
            "Veredicto:N",
            scale=alt.Scale(
                domain=[ui.VERDICT_LABEL[v] for v in ui.VERDICT_ORDER],
                range=[ui.VERDICT_COLOR[v] for v in ui.VERDICT_ORDER],
            ),
            legend=alt.Legend(orient="top", title=None),
        ),
        tooltip=["Regla", "Veredicto", "count()"],
    )
)
st.altair_chart(chart_rule, use_container_width=True)

# ── Mapa de calor: severidad regla vs. severidad final ────────────────────────
st.subheader("Severidad de la regla frente a severidad final")
df_heat = pd.DataFrame([
    {"Sev. regla": ui.SEVERITY_LABEL.get(r["rule_severity"], r["rule_severity"]),
     "Sev. final": ui.SEVERITY_LABEL.get(r.get("severity") or "medium", r.get("severity", ""))}
    for r in rows
])
pivot = df_heat.groupby(["Sev. regla", "Sev. final"]).size().reset_index(name="n")
sev_labels_ordered = [ui.SEVERITY_LABEL[s] for s in SEVERITY_ORDER]
heatmap = (
    alt.Chart(pivot)
    .mark_rect()
    .encode(
        x=alt.X("Sev. regla:N", sort=sev_labels_ordered, title="Severidad de la regla"),
        y=alt.Y("Sev. final:N", sort=sev_labels_ordered[::-1], title="Severidad final"),
        color=alt.Color("n:Q", scale=alt.Scale(scheme="blues"), title="Alertas"),
        tooltip=["Sev. regla", "Sev. final", "n"],
    )
    .properties(height=200)
)
text_layer = (
    alt.Chart(pivot)
    .mark_text(baseline="middle", fontSize=13, fontWeight="bold")
    .encode(
        x=alt.X("Sev. regla:N", sort=sev_labels_ordered),
        y=alt.Y("Sev. final:N", sort=sev_labels_ordered[::-1]),
        text=alt.Text("n:Q"),
        color=alt.condition(alt.datum.n > pivot["n"].max() / 2, alt.value("white"), alt.value("#333")),
    )
)
st.altair_chart(heatmap + text_layer, use_container_width=True)

# ── Alertas por día (barras apiladas) ─────────────────────────────────────────
st.subheader("Alertas por día")
df_day = pd.DataFrame([
    {"Día": r["created_at"][:10],
     "Decisión": "Cerradas" if r["decision"] == "close" else "Escaladas"}
    for r in rows if r.get("created_at")
])
if not df_day.empty:
    chart_day = (
        alt.Chart(df_day)
        .mark_bar()
        .encode(
            x=alt.X("Día:T", title="Fecha"),
            y=alt.Y("count():Q", title="Alertas"),
            color=alt.Color(
                "Decisión:N",
                scale=alt.Scale(
                    domain=["Cerradas", "Escaladas"],
                    range=[ui.DECISION_COLOR["close"], ui.DECISION_COLOR["escalate"]],
                ),
                legend=alt.Legend(orient="top", title=None),
            ),
            tooltip=["Día", "Decisión", "count()"],
        )
    )
    st.altair_chart(chart_day, use_container_width=True)

# ── SLA de las escaladas (se actualiza cada 10 s) ─────────────────────────────

@st.fragment(run_every="10s")
def sla_table():
    """Tabla de SLA para las alertas escaladas, actualizada automáticamente."""
    st.subheader("SLA de las escaladas")
    now = dt.datetime.now(dt.timezone.utc)
    escalated = [r for r in data.load_results() if r["decision"] == "escalate"]
    if not escalated:
        st.info("No hay alertas escaladas todavía.")
        return

    filas = []
    for r in escalated:
        sev = r.get("severity") or "medium"
        limit_min = SLA_MIN.get(sev, 240)
        try:
            created = dt.datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
        except Exception:
            created = now
        elapsed = (now - created).total_seconds() / 60
        remaining = limit_min - elapsed
        review = r.get("review")
        filas.append({
            "ID": r["alert_id"],
            "Regla": r["rule_name"],
            "Sev.": ui.SEVERITY_LABEL.get(sev, sev),
            "Revisada": "✅ " + (review["analyst"] if review else "") if review else "⏳ Pendiente",
            "Límite SLA": f"{limit_min} min",
            "Tiempo restante (min)": f"{remaining:.0f}",
            "_vencida": remaining < 0 and not review,
        })

    df_sla = pd.DataFrame(filas)
    vencidas = df_sla["_vencida"].sum()
    if vencidas:
        st.warning(f"⚠️ {vencidas} alerta(s) han superado el SLA sin revisión.")
    df_show = df_sla.drop(columns=["_vencida"])

    def _color_row(row):
        venc = filas[row.name]["_vencida"]
        color = "background-color: #fde8e8" if venc else ""
        return [color] * len(row)

    st.dataframe(
        df_show.style.apply(_color_row, axis=1),
        hide_index=True,
        use_container_width=True,
    )
    st.caption(f"SLA: crítica {SLA_MIN['critical']} min · alta {SLA_MIN['high']} min · "
               f"media {SLA_MIN['medium'] // 60} h · baja {SLA_MIN['low'] // 60} h. "
               f"Se actualiza cada 10 s.")


sla_table()
