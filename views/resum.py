"""Panel de negocio + SLA. Textos en catalán.

Dueño: PERSONA B. Métricas, reparto por veredicto y por regla, mapa de calor de gravedad, alertas por día
y SLA de las escaladas (@st.fragment, se refresca cada 10 s). Colores SIEMPRE de core/ui.py.
"""
import datetime as dt
from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

from core import data, ui

MIN_PER_ALERT = 8  # supuesto: minutos de un analista N1 por alerta triada a mano

# SLA por severidad (en minutos)
SLA_MIN = {"critical": 15, "high": 30, "medium": 240, "low": 1440, "informational": 1440}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
CLOSED, ESCALATED = "Tancades", "Escalades"

st.title("Resum")
st.markdown('<p class="muted">La foto de conjunt per a la direcció: quanta feina estalvia el sistema, quin tipus '
            "d'avisos arriben i quins casos escalats tenen pressa.</p>", unsafe_allow_html=True)
rows = data.load_results()
if not rows:
    ui.empty_state("dades per resumir")
n = len(rows)
closed = sum(r["decision"] == "close" for r in rows)
m = st.columns(4)
m[0].metric("Alertes revisades", n)
m[1].metric("Es tanquen sense intervenció", f"{round(100 * closed / max(1, n))} %")
m[2].metric("Necessiten una persona", n - closed)
m[3].metric("Hores d'analista estalviades", f"{closed * MIN_PER_ALERT / 60:.1f} h",
            help=f"Suposició: {MIN_PER_ALERT} min per alerta triada a mà. "
                 f"Només les {closed} tancades automàticament eviten la revisió manual.")

# ── Reparto por veredicto (barra al 100 %) ────────────────────────────────────
st.subheader("Què conclou el sistema", anchor=False)
_cnt_v = Counter(ui.VERDICT_LABEL[r["verdict"]] for r in rows)
# Barra única apilada al 100 %: necesita un eje y fijo ("y") para que Vega pinte una sola fila.
_verd_vals = [{"Veredicte": k, "n": int(v), "pct": round(100 * v / max(1, n), 1), "y": "Alertes"}
              for k, v in _cnt_v.items()]
bar100 = (
    alt.Chart(alt.Data(values=_verd_vals))
    .mark_bar()
    .encode(
        x=alt.X("n:Q", title=None, stack="normalize",
                axis=alt.Axis(format=".0%", grid=False)),
        color=alt.Color(
            "Veredicte:N",
            scale=alt.Scale(
                domain=[ui.VERDICT_LABEL[v] for v in ui.VERDICT_ORDER],
                range=[ui.VERDICT_COLOR[v] for v in ui.VERDICT_ORDER],
            ),
            legend=alt.Legend(orient="top", title=None),
        ),
        y=alt.Y("y:N", title=None, axis=None),
        tooltip=["Veredicte:N", alt.Tooltip("n:Q", title="Alertes"), alt.Tooltip("pct:Q", format=".1f", title="%")],
    )
    # Sin .properties(height=…): con altura fija Streamlit no pinta la barra.
)
st.altair_chart(bar100, use_container_width=True)

# ── Veredicto por regla (barras horizontales apiladas) ────────────────────────
st.subheader("Què conclou, per tipus d'avís", anchor=False)
df_rule = pd.DataFrame([{"Regla": r["rule_name"], "Veredicte": ui.VERDICT_LABEL[r["verdict"]]} for r in rows])
top_rules = df_rule["Regla"].value_counts().head(9).index.tolist()
df_rule["Regla"] = df_rule["Regla"].where(df_rule["Regla"].isin(top_rules), "Altres")
chart_rule = (
    alt.Chart(df_rule)
    .mark_bar()
    .encode(
        y=alt.Y("Regla:N", sort="-x", title=None, axis=alt.Axis(labelLimit=320)),
        x=alt.X("count():Q", title="Alertes"),
        color=alt.Color(
            "Veredicte:N",
            scale=alt.Scale(
                domain=[ui.VERDICT_LABEL[v] for v in ui.VERDICT_ORDER],
                range=[ui.VERDICT_COLOR[v] for v in ui.VERDICT_ORDER],
            ),
            legend=alt.Legend(orient="top", title=None),
        ),
        tooltip=["Regla", "Veredicte", alt.Tooltip("count()", title="Alertes")],
    )
)
st.altair_chart(chart_rule, use_container_width=True)

# ── Mapa de calor: severidad regla vs. severidad final ────────────────────────
st.subheader("Gravetat de la regla davant de la gravetat final", anchor=False)
st.caption("Cada casella compta alertes. El que cau fora de la diagonal és el que ha canviat en tenir en compte "
           "quin equip i quina persona estan afectats i què ha conclòs el sistema.")
_cnt_h = Counter((ui.SEVERITY_LABEL.get(r["rule_severity"], r["rule_severity"]),
                  ui.SEVERITY_LABEL.get(r.get("severity") or "medium", r.get("severity", ""))) for r in rows)
_heat_vals = [{"Regla": a, "Final": b, "n": int(c)} for (a, b), c in _cnt_h.items()]
_heat_max = max((v["n"] for v in _heat_vals), default=1)
sev_labels_ordered = [ui.SEVERITY_LABEL[s] for s in SEVERITY_ORDER]
heatmap = (
    alt.Chart(alt.Data(values=_heat_vals))
    .mark_rect()
    .encode(
        x=alt.X("Regla:N", sort=sev_labels_ordered, title="Gravetat de la regla"),
        y=alt.Y("Final:N", sort=sev_labels_ordered[::-1], title="Gravetat final"),
        color=alt.Color("n:Q", scale=alt.Scale(scheme="blues"), title="Alertes"),
        tooltip=["Regla:N", "Final:N", alt.Tooltip("n:Q", title="Alertes")],
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
st.subheader("Alertes per dia", anchor=False)
df_day = pd.DataFrame([
    {"Dia": r["created_at"][:10], "Decisió": CLOSED if r["decision"] == "close" else ESCALATED}
    for r in rows if r.get("created_at")
])
if not df_day.empty:
    chart_day = (
        alt.Chart(df_day)
        .mark_bar()
        .encode(
            x=alt.X("Dia:T", title="Data"),
            y=alt.Y("count():Q", title="Alertes"),
            color=alt.Color(
                "Decisió:N",
                scale=alt.Scale(
                    domain=[CLOSED, ESCALATED],
                    range=[ui.DECISION_COLOR["close"], ui.DECISION_COLOR["escalate"]],
                ),
                legend=alt.Legend(orient="top", title=None),
            ),
            tooltip=["Dia", "Decisió", alt.Tooltip("count()", title="Alertes")],
        )
    )
    st.altair_chart(chart_day, use_container_width=True)

# ── SLA de las escaladas (se actualiza cada 10 s) ─────────────────────────────

SESSION_T0 = st.session_state.setdefault("panel_t0", dt.datetime.now(dt.timezone.utc))


@st.fragment(run_every="10s")
def sla_table():
    """Tabla de SLA para las alertas escaladas, actualizada automáticamente."""
    st.subheader("Terminis de les alertes escalades (SLA)", anchor=False)
    now = dt.datetime.now(dt.timezone.utc)
    if not any(r.get("triaged_at") for r in data.load_results()):
        st.caption("Els terminis compten des que s'ha obert aquesta pantalla, com si les alertes acabessin d'entrar.")
    escalated = [r for r in data.load_results() if r["decision"] == "escalate"]
    if not escalated:
        st.info("Encara no hi ha alertes escalades.")
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
            "Gravetat": ui.SEVERITY_LABEL.get(sev, sev),
            "Revisada": f"Per {review['analyst']}" if review else "Pendent",
            "Límit SLA": f"{limit_min} min",
            "Queda": (f"{remaining:.0f} min" if remaining >= 0 else f"vençuda fa {-remaining:.0f} min")
                     if not review else "—",
            "_vencida": remaining < 0 and not review,
        })

    df_sla = pd.DataFrame(filas)
    vencidas = df_sla["_vencida"].sum()
    if vencidas:
        st.warning(f"{vencidas} alerta(es) han superat el termini sense que ningú les revisi.")
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
               f"mitjana {SLA_MIN['medium'] // 60} h · baixa {SLA_MIN['low'] // 60} h. "
               f"S'actualitza cada 10 s.")


sla_table()
