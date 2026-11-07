"""Incidentes: varias alertas del mismo ataque agrupadas (niveles 2-3, solo si hay tiempo).

Dueño: PERSONA B. Esqueleto: agrupa por incident_id. En el fixture hay un incidente de ejemplo
(INC-EJ-001: dos correos del mismo proveedor falso con texto oculto para el clasificador).
Pendiente:
  - TODO B: tarjeta de incidente (entidades compartidas, severidad máxima).
  - TODO B: línea temporal del incidente con fases MITRE (Altair).
"""
import pandas as pd
import streamlit as st

from core import data, ui

st.title("Incidentes")
rows = data.load_results()
groups: dict[str, list] = {}
for r in rows:
    if r["incident_id"]:
        groups.setdefault(r["incident_id"], []).append(r)

if not groups:
    st.info("Todavía no hay incidentes: el back no genera incident_id.")
for inc, alerts in groups.items():
    example = any("incident_id" in r["example_fields"] for r in alerts)
    st.subheader(f"{inc} · {len(alerts)} alertas" + (" (ejemplo)" if example else ""))
    st.dataframe(pd.DataFrame([{"Hora": ui.fmt_time(r["created_at"]), "ID": r["alert_id"], "Regla": r["rule_name"],
                                "Veredicto": ui.VERDICT_LABEL[r["verdict"]],
                                "Severidad": ui.SEVERITY_LABEL[r["severity"]]} for r in alerts]),
                 hide_index=True, use_container_width=True)
