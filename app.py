from __future__ import annotations

import json
from pathlib import Path

import streamlit as st
import ollama

from soc_api import SocAPIError, list_alerts
from triage import analyze_alert

SCHEMA_PATH = Path(__file__).parent / "ticket_salida.schema.json"
TICKET_SCHEMA = {}
if SCHEMA_PATH.exists():
    try:
        with open(SCHEMA_PATH, encoding="utf-8") as f:
            TICKET_SCHEMA = json.load(f)
    except Exception:
        TICKET_SCHEMA = {}


st.set_page_config(
    page_title="Tarvia SOC | Triaje asistido",
    page_icon="🛡️",
    layout="wide",
)

st.title("Tarvia SOC · Triaje asistido")
st.caption(
    "MVP local · La aplicación consulta la API simulada, investiga contexto e indicadores, "
    "y decide el veredicto conforme a la política del SOC y los runbooks (RB01-RB10)."
)

with st.sidebar:
    st.header("Cola de alertas")
    limit = st.slider("Alertas por cargar", min_value=5, max_value=100, value=30, step=5)
    refresh = st.button("Actualizar cola", use_container_width=True)
    st.divider()

    st.header("Opciones de Triaje e IA")
    use_llm = st.toggle(
        "Decidir veredicto con LLM (Ollama)",
        value=False,
        help="Si está activado, consulta a Ollama localmente para evaluar el veredicto. Si Ollama no responde, se recurre automáticamente al motor de reglas del SOC.",
    )
    selected_model = st.text_input(
        "Modelo Ollama",
        value="llama3",
        help="Nombre del modelo instalado en tu Ollama local (ej. llama3, mistral, gemma2)",
    )
    st.divider()
    st.caption("API simulada: http://127.0.0.1:8000")

if refresh or "alert_items" not in st.session_state:
    try:
        with st.spinner("Consultando la API SOC…"):
            payload = list_alerts(status="new", limit=limit)
        st.session_state["alert_items"] = payload.get("items", [])
        st.session_state["alert_total"] = payload.get("total", len(payload.get("items", [])))
        st.session_state.pop("triage_preview", None)
    except SocAPIError as exc:
        st.session_state.pop("alert_items", None)
        st.error(f"No se pudo cargar la cola: {exc}")
        st.info("Comprueba que la API simulada sigue ejecutándose en el puerto 8000.")
        st.stop()

items = st.session_state.get("alert_items", [])
if not items:
    st.info("La API no devolvió alertas nuevas para mostrar.")
    st.stop()

st.metric("Alertas nuevas disponibles", st.session_state.get("alert_total", len(items)))

rows = [
    {
        "ID": item.get("alert_id", ""),
        "Hora UTC": item.get("created_at", ""),
        "Fuente": item.get("source_product", ""),
        "Regla": item.get("rule_name", ""),
        "Severidad regla": item.get("severity", ""),
        "Estado": item.get("status", ""),
    }
    for item in items
]
st.dataframe(rows, hide_index=True, use_container_width=True)

by_id = {item["alert_id"]: item for item in items if item.get("alert_id")}
selected_id = st.selectbox(
    "Selecciona una alerta para investigar",
    options=list(by_id),
    format_func=lambda alert_id: (
        f"{alert_id} · {by_id[alert_id].get('source_product', '?')} · "
        f"{by_id[alert_id].get('rule_name', 'Sin regla')}"
    ),
)

left, right = st.columns([1, 4])
with left:
    investigate = st.button("Investigar alerta", type="primary", use_container_width=True)
with right:
    engine_desc = f"LLM ({selected_model})" if use_llm else "Motor de reglas del SOC (Runbooks RB01-RB10)"
    st.caption(f"Evaluación configurada: **{engine_desc}**. Consultando API SOC local.")

if investigate:
    try:
        spinner_msg = f"Consultando contexto y decidiendo veredicto con {engine_desc}…"
        with st.spinner(spinner_msg):
            preview = analyze_alert(selected_id, use_llm=use_llm, model=selected_model)
        st.session_state["triage_preview"] = preview.model_dump()
    except SocAPIError as exc:
        st.error(f"La API no pudo completar la investigación: {exc}")
        st.stop()
    except Exception as exc:
        st.error(f"Error inesperado durante el triaje: {exc}")
        st.stop()

preview_data = st.session_state.get("triage_preview")
if preview_data and preview_data.get("alert", {}).get("alert_id") == selected_id:
    st.divider()
    st.subheader("Resultado de la Investigación y Triaje N1")
    alert = preview_data["alert"]
    verdict = preview_data.get("verdict", "needs_more_info")
    confidence = preview_data.get("confidence", 0.5)
    decision_engine = preview_data.get("decision_engine", "rules")

    # Banner visual de veredicto
    if verdict == "true_positive":
        st.error(f"🔴 **Veredicto: TRUE POSITIVE (Incidente Malicioso Confirmado)** · Confianza: **{confidence:.0%}** · Motor: `{decision_engine}`")
    elif verdict == "benign_true_positive":
        st.success(f"🟢 **Veredicto: BENIGN TRUE POSITIVE (Detección Real pero Actividad Autorizada)** · Confianza: **{confidence:.0%}** · Motor: `{decision_engine}`")
    elif verdict == "false_positive":
        st.info(f"⚪ **Veredicto: FALSE POSITIVE (Falsa Alarma / Sin Riesgo)** · Confianza: **{confidence:.0%}** · Motor: `{decision_engine}`")
    else:
        st.warning(f"🟠 **Veredicto: NEEDS MORE INFO (Requiere Investigación Manual Adicional)** · Confianza: **{confidence:.0%}** · Motor: `{decision_engine}`")

    metric1, metric2, metric3, metric4 = st.columns(4)
    metric1.metric("Veredicto", verdict)
    metric2.metric("Severidad calculada", preview_data["severity"].upper())
    metric3.metric("Confianza", f"{confidence:.0%}")
    metric4.metric("Fuente", alert.get("source_product", "desconocida"))

    st.markdown(f"**Regla:** `{alert.get('rule_id', 'N/A')}` — **{alert.get('rule_name', 'Sin nombre')}**")
    st.write("**Justificación del veredicto:**", preview_data.get("verdict_rationale", "Sin justificación."))
    st.write("**Justificación de severidad:**", preview_data.get("severity_rationale", "Sin justificación."))

    # Alerta de escalado a N2
    escalation = preview_data.get("escalation", {})
    if escalation.get("escalate"):
        st.error(f"🚨 **Escalado obligatorio a {escalation.get('to', 'N2')}**: {escalation.get('reason', 'Incidente relevante')}")
    else:
        st.caption("✅ Cierre en N1: No requiere escalado obligatorio según la política del SOC.")

    # Acciones recomendadas
    actions = preview_data.get("recommended_actions", [])
    if actions:
        st.markdown("#### Acciones de contención y respuesta propuestas")
        action_rows = [
            {
                "Acción": a.get("action", ""),
                "Objetivo": a.get("target", ""),
                "Aprobación": "⚠️ Requiere aprobación (N2)" if a.get("requires_approval") else "✅ Ejecución directa N1",
                "Justificación": a.get("justification", ""),
            }
            for a in actions
        ]
        st.dataframe(action_rows, hide_index=True, use_container_width=True)

    questions = preview_data.get("open_questions", [])
    if questions:
        st.markdown("#### Puntos pendientes de confirmar")
        for question in questions:
            st.markdown(f"- {question}")

    tab_queries, tab_context, tab_logs, tab_ticket, tab_alert = st.tabs(
        ["Consultas realizadas", "Contexto", "Logs relacionados", "Ticket N1 (JSON)", "Alerta original"]
    )
    with tab_queries:
        st.dataframe(preview_data.get("queries", []), hide_index=True, use_container_width=True)
    with tab_context:
        contexts = preview_data.get("contexts", [])
        if not contexts:
            st.info("No se obtuvo contexto adicional.")
        for index, context in enumerate(contexts):
            label = f"{context.get('kind', 'dato')} · {context.get('key', '')}"
            with st.expander(label, expanded=index == 0):
                st.json(context.get("data", {}))
    with tab_logs:
        logs = preview_data.get("related_logs", [])
        if logs:
            st.dataframe(logs, hide_index=True, use_container_width=True)
        else:
            st.info("No se encontraron logs relacionados en las consultas realizadas.")
    with tab_ticket:
        ticket = preview_data.get("ticket")
        if ticket:
            st.download_button(
                label="📥 Descargar Ticket JSON",
                data=json.dumps(ticket, indent=2, ensure_ascii=False),
                file_name=f"ticket_{alert.get('alert_id', 'alr')}.json",
                mime="application/json",
            )
            st.json(ticket)
        else:
            st.info("Ticket no disponible.")
    with tab_alert:
        st.json(alert)

    st.divider()
    st.subheader("Plan de Acción y Análisis Asistido por LLM")

    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        generate_llm = st.button("Generar análisis LLM con Ollama", type="secondary", use_container_width=True)
    with col_info:
        st.caption(f"Genera un informe detallado con `{selected_model}` siguiendo el esquema del ticket.")

    if generate_llm:
        context_data = {
            "alerta": alert.get("rule_name"),
            "severitat": preview_data.get("severity"),
            "veredicte": preview_data.get("verdict"),
            "justificacio_veredicte": preview_data.get("verdict_rationale"),
            "preguntes_obertes": preview_data.get("open_questions", []),
            "context_addicional": preview_data.get("contexts", []),
            "accions_recomanades": preview_data.get("recommended_actions", []),
        }

        prompt = (
            "Ets un analista expert d'un SOC (Centre d'Operacions de Seguretat) de Tarvia Group.\n"
            "Analitza l'alerta i genera les conclusions detallades, el pla d'acció i el resum per a l'analista N2.\n"
            f"Dades de l'alerta i triatge preliminar:\n{json.dumps(context_data, indent=2, ensure_ascii=False)}"
        )

        try:
            with st.spinner("Analitzant amb Ollama..."):
                response_stream = ollama.chat(
                    model=selected_model,
                    messages=[{"role": "user", "content": prompt}],
                    stream=True,
                )

                def stream_parser():
                    for chunk in response_stream:
                        yield chunk["message"]["content"]

                st.write_stream(stream_parser)
        except Exception as exc:
            st.error(
                f"Error al connectar amb Ollama. Comprova que el servei s'està executant (`ollama serve`). Detall: {exc}"
            )
else:
    st.info("Selecciona una alerta y pulsa **Investigar alerta** para recopilar evidencias.")
