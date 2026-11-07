"""Panel de negocio + SLA.

Dueño: PERSONA B. Punto de partida: métricas y un gráfico. Colores SIEMPRE de core/ui.py.
Pendiente (ver la maqueta demo/triaje_demo.html, vista Panel):
  - TODO B: severidad de la regla frente a severidad final (mapa de calor).
  - TODO B: alertas por día, apiladas por decisión.
  - TODO B: SLA de las escaladas con @st.fragment (hecho).


@st.fragment(run_every="10s").
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

st.title("Resumen")
st.markdown('<p class="muted">La foto de conjunto para dirección: cuánto trabajo quita el sistema, qué tipo de '
            "avisos llegan y qué casos escalados corren prisa.</p>", unsafe_allow_html=True)
rows = data.load_results()
if not rows:
    ui.empty_state("datos que resumir")
n = len(rows)
closed = sum(r["decision"] == "close" for r in rows)
m = st.columns(4)
m[0].metric("Alertas revisadas", n)
m[1].metric("Se cierran sin intervención", f"{round(100 * closed / max(1, n))} %")
m[2].metric("Necesitan a una persona", n - closed)
m[3].metric("Horas de analista ahorradas", f"{closed * MIN_PER_ALERT / 60:.1f} h",
            help=f"Supuesto: {MIN_PER_ALERT} min por alerta triada a mano. "
                 f"Solo las {closed} cerradas automáticamente evitan la revisión manual.")

if any("verdict" in r["example_fields"] for r in rows):
    st.caption("Los veredictos y decisiones son de ejemplo (reglas de prueba) hasta que el back los genere.")

# ── Reparto por veredicto (barra al 100 %) ────────────────────────────────────
st.subheader("Qué concluye el sistema", anchor=False)
from collections import Counter  # noqa: E402

_cnt_v = Counter(ui.VERDICT_LABEL[r["verdict"]] for r in rows)
# Barra única apilada al 100 %: necesita un eje y fijo ("y") para que Vega pinte una sola fila.
_verd_vals = [{"Veredicto": k, "n": int(v), "pct": round(100 * v / max(1, n), 1), "y": "Alertas"}
              for k, v in _cnt_v.items()]
bar100 = (
    alt.Chart(alt.Data(values=_verd_vals))
    .mark_bar()
    .encode(
        x=alt.X("n:Q", title=None, stack="normalize",
                axis=alt.Axis(format=".0%", grid=False)),
        color=alt.Color(
            "Veredicto:N",
            scale=alt.Scale(
                domain=[ui.VERDICT_LABEL[v] for v in ui.VERDICT_ORDER],
                range=[ui.VERDICT_COLOR[v] for v in ui.VERDICT_ORDER],
            ),
            legend=alt.Legend(orient="top", title=None),
        ),
        y=alt.Y("y:N", title=None, axis=None),
        tooltip=["Veredicto:N", alt.Tooltip("n:Q", title="Alertas"), alt.Tooltip("pct:Q", format=".1f", title="%")],
    )
    # Sin .properties(height=…): con altura fija Streamlit no pinta la barra.
)
st.altair_chart(bar100, use_container_width=True)

# ── Veredicto por regla (barras horizontales apiladas) ────────────────────────
st.subheader("Qué concluye, por tipo de aviso", anchor=False)
df_rule = pd.DataFrame([{"Regla": r["rule_name"], "Veredicto": ui.VERDICT_LABEL[r["verdict"]]} for r in rows])
top_rules = df_rule["Regla"].value_counts().head(9).index.tolist()
df_rule["Regla"] = df_rule["Regla"].where(df_rule["Regla"].isin(top_rules), "Otras")
chart_rule = (
    alt.Chart(df_rule)
    .mark_bar()
    .encode(
        y=alt.Y("Regla:N", sort="-x", title=None, axis=alt.Axis(labelLimit=320)),
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
st.subheader("Gravedad de la regla frente a gravedad final", anchor=False)
st.caption("Cada casilla cuenta alertas. Lo que cae fuera de la diagonal es lo que ha cambiado al tener en cuenta "
           "qué equipo y qué persona están afectados.")
_cnt_h = Counter((ui.SEVERITY_LABEL.get(r["rule_severity"], r["rule_severity"]),
                  ui.SEVERITY_LABEL.get(r.get("severity") or "medium", r.get("severity", ""))) for r in rows)
_heat_vals = [{"Regla": a, "Final": b, "n": int(c)} for (a, b), c in _cnt_h.items()]
_heat_max = max((v["n"] for v in _heat_vals), default=1)
sev_labels_ordered = [ui.SEVERITY_LABEL[s] for s in SEVERITY_ORDER]
heatmap = (
    alt.Chart(alt.Data(values=_heat_vals))
    .mark_rect()
    .encode(
        x=alt.X("Regla:N", sort=sev_labels_ordered, title="Gravedad de la regla"),
        y=alt.Y("Final:N", sort=sev_labels_ordered[::-1], title="Gravedad final"),
        color=alt.Color("n:Q", scale=alt.Scale(scheme="blues"), title="Alertas"),
        tooltip=["Regla:N", "Final:N", "n:Q"],
    )
    .properties(height=200)
)
text_layer = (
    alt.Chart(alt.Data(values=_heat_vals))
    .mark_text(baseline="middle", fontSize=13, fontWeight="bold")
    .encode(
        x=alt.X("Regla:N", sort=sev_labels_ordered),
        y=alt.Y("Final:N", sort=sev_labels_ordered[::-1]),
        text=alt.Text("n:Q"),
        color=alt.condition(alt.datum.n > _heat_max / 2, alt.value("white"), alt.value("#333")),
    )
)
st.altair_chart(heatmap + text_layer, use_container_width=True)

# ── Alertas por día (barras apiladas) ─────────────────────────────────────────
st.subheader("Alertas por día", anchor=False)
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

SESSION_T0 = st.session_state.setdefault("panel_t0", dt.datetime.now(dt.timezone.utc))


@st.fragment(run_every="10s")
def sla_table():
    """Tabla de SLA para las alertas escaladas, actualizada automáticamente."""
    st.subheader("Plazos de las alertas escaladas (SLA)", anchor=False)
    now = dt.datetime.now(dt.timezone.utc)
    if not any(r.get("triaged_at") for r in data.load_results()):
        st.caption("La muestra no trae la hora de triaje: los plazos cuentan desde que se abrió esta pantalla.")
    escalated = [r for r in data.load_results() if r["decision"] == "escalate"]
    if not escalated:
        st.info("No hay alertas escaladas todavía.")
        return

    filas = []
    for r in escalated:
        sev = r.get("severity") or "medium"
        limit_min = SLA_MIN.get(sev, 240)
        # El plazo corre desde que el sistema la trió (triaged_at). La muestra no lo trae:
        # se toma la hora en que se abrió esta sesión, como si acabaran de entrar.
        try:
            created = dt.datetime.fromisoformat(r["triaged_at"].replace("Z", "+00:00"))
        except Exception:
            created = SESSION_T0
        elapsed = (now - created).total_seconds() / 60
        remaining = limit_min - elapsed
        review = r.get("review")
        filas.append({
            "ID": r["alert_id"],
            "Regla": r["rule_name"],
            "Sev.": ui.SEVERITY_LABEL.get(sev, sev),
            "Revisada": "✅ " + (review["analyst"] if review else "") if review else "⏳ Pendiente",
            "Límite SLA": f"{limit_min} min",
            "Queda": (f"{remaining:.0f} min" if remaining >= 0 else f"vencida hace {-remaining:.0f} min")
                      if not review else "—",
            "_vencida": remaining < 0 and not review,
        })

    df_sla = pd.DataFrame(filas)
    vencidas = df_sla["_vencida"].sum()
    if vencidas:
        st.warning(f"{vencidas} alerta(s) han superado su plazo sin que nadie las revise.", icon="⚠️")
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
