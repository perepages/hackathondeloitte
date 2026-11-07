"""Contención con aprobación humana (nivel 4, solo si hay tiempo).

Dueño: PERSONA A. Esqueleto: lista lo que habría que aprobar. data.approve() y data.contain()
ya existen (simulados en modo fixture, reales contra la API en modo live).
Pendiente:
  - TODO A: flujo propuesta -> aprobar (nombre + motivo) -> ejecutar -> registro.
  - TODO A: block_ioc y purge_email sin aprobación; acciones sobre la red OT deshabilitadas
    («Escalar a Operaciones»).
"""
import pandas as pd
import streamlit as st

from core import data, ui

st.title("Contención")
st.caption("Nivel 4 · el sistema propone, la persona aprueba, y solo entonces se ejecuta en la API simulada.")

rows = [r for r in data.load_results() if r["decision"] == "escalate"]
acts = [{"Alerta": r["alert_id"], "Acción": ui.ACTION_LABEL.get(a["action"], a["action"]), "Objetivo": a["target"],
         "Requiere aprobación": "sí" if a["requires_approval"] else "no", "Motivo": a.get("justification", "")}
        for r in rows for a in r["recommended_actions"] if a["action"] not in ("close", "escalate")]
st.dataframe(pd.DataFrame(acts), hide_index=True, use_container_width=True)
st.info("Pendiente de diseñar: aprobar y ejecutar cada acción, con registro de quién lo aprobó.")
