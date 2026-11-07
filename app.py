from __future__ import annotations

import streamlit as st
import json
import ollama

from soc_api import SocAPIError, list_alerts
from triage import analyze_alert


st.set_page_config(
    page_title="Tarvia SOC | Triaje",
    page_icon="🛡️",
    layout="wide",
)

st.title("Tarvia SOC · Triaje asistido")
st.caption(
    "MVP local · La aplicación consulta la API simulada y reúne evidencias. "
    "Las conclusiones todavía requieren revisión humana."
)

with st.sidebar:
    st.header("Cola de alertas")
    limit = st.slider("Alertas por cargar", min_value=5, max_value=100, value=30, step=5)
    refresh = st.button("Actualizar cola", use_container_width=True)
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

left, right = st.columns([1, 5])
with left:
    investigate = st.button("Investigar alerta", type="primary", use_container_width=True)
with right:
    st.caption("La investigación consulta solo herramientas documentadas de la API local.")

if investigate:
    try:
        with st.spinner("Consultando contexto e investigando eventos relacionados…"):
            preview = analyze_alert(selected_id)
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
    st.subheader("Resultado preliminar")
    alert = preview_data["alert"]
    metric1, metric2, metric3 = st.columns(3)
    metric1.metric("Veredicto", preview_data["verdict"])
    metric2.metric("Severidad calculada", preview_data["severity"])
    metric3.metric("Fuente", alert.get("source_product", "desconocida"))
    st.write("**Regla:**", alert.get("rule_name", "Sin nombre"))
    st.write("**Justificación de severidad:**", preview_data["severity_rationale"])
    st.warning(
        "Es un resultado preliminar (`needs_more_info`), no una decisión final ni un ticket aprobado. "
        "El LLM aún no está conectado y no se ejecuta ninguna acción de contención."
    )

    questions = preview_data.get("open_questions", [])
    if questions:
        st.markdown("#### Pendiente de confirmar")
        for question in questions:
            st.markdown(f"- {question}")

    tab_queries, tab_context, tab_logs, tab_alert = st.tabs(
        ["Consultas realizadas", "Contexto", "Logs relacionados", "Alerta original"]
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
    with tab_alert:
        st.json(alert)
    st.divider()
    st.subheader(" Pla d'Acció Recomanat ")
    
    # Selecció del model d'Ollama instal·lat localment
    ruta = r"C:\Users\OneDrive\Documents\GitHub\hackathondeloitte\ticket_salida.schema.json"
    selected_model = "llama3"

    if st.button("Generar resum d'accions", type="primary", use_container_width=True):
        # 1. Preparar les dades rellevants per passar-les com a context
        context_data = {
            "alerta": alert.get("rule_name"),
            "severitat": preview_data.get("severity"),
            "veredicte": preview_data.get("verdict"),
            "preguntes_obertes": preview_data.get("open_questions", []),
            "context_addicional": preview_data.get("contexts", [])
        }
        
        prompt = (
            "Ets un analista expert d'un SOC (Centre d'Operacions de Seguretat). "
            f"A partir de la seguent estructura, completa amb les dades que proporcionem i els resultats adhients: {ruta})"
            "Expressa les conclusions en el format JSON de l'esquema proveït. Omple totes les caselles, tot i que ja tinguem l'informació en el context"
            f"Dades de l'alerta:\n{json.dumps(context_data, indent=2, ensure_ascii=False)}"
        )

        try:
            with st.spinner("Analitzant..."):
                # 2. Cridar l'API local d'Ollama en mode stream per a millor UX
                response_stream = ollama.chat(
                    model=selected_model,
                    messages=[{"role": "user", "content": prompt}],
                    stream=True
                )
                
                # 3. Funció generadora per iterar sobre els fragments de text
                def stream_parser():
                    for chunk in response_stream:
                        yield chunk['message']['content']
                        
                # 4. Mostrar la resposta escrivint-la en temps real
                st.write_stream(stream_parser)
                
        except Exception as exc:
            st.error(f"Error al connectar amb Ollama. Comprova que el servei s'està executant (`ollama serve`). Detall: {exc}")
else:
    st.info("Selecciona una alerta y pulsa **Investigar alerta** para recopilar evidencias.")
