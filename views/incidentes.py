"""Incidentes: varias alertas del mismo ataque agrupadas (niveles 2-3, solo si hay tiempo).

Dueño: PERSONA B. Esqueleto: agrupa por incident_id. En el fixture hay un incidente de ejemplo
(INC-EJ-001: dos correos del mismo proveedor falso con texto oculto para el clasificador).
Pendiente:
  - TODO B: tarjeta de incidente (entidades compartidas, severidad máxima).
  - TODO B: línea temporal del incidente con fases MITRE (Altair).
"""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from core import data, ui

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

st.title("Incidentes")
rows = data.load_results()
groups: dict[str, list] = {}
for r in rows:
    if r["incident_id"]:
        groups.setdefault(r["incident_id"], []).append(r)

if not groups:
    st.info("Todavía no hay incidentes: el back no genera incident_id.")


def _shared_entities(alerts: list[dict]) -> dict:
    """Devuelve listas de entidades (hosts, users, IPs, dominios) compartidas entre ≥2 alertas."""
    from collections import Counter
    hosts: Counter = Counter()
    users: Counter = Counter()
    ips: Counter = Counter()
    domains: Counter = Counter()
    for a in alerts:
        ent = a["alert"].get("entities") or {}
        for h in ent.get("hosts") or []:
            if h.get("hostname"):
                hosts[h["hostname"]] += 1
            if h.get("ip"):
                ips[h["ip"]] += 1
        for u in ent.get("users") or []:
            if u.get("username"):
                users[u["username"]] += 1
        for d in ent.get("domains") or []:
            if isinstance(d, str):
                domains[d] += 1
            elif isinstance(d, dict) and d.get("domain"):
                domains[d["domain"]] += 1
    n = len(alerts)
    return {
        "hosts": [k for k, c in hosts.items() if c >= min(2, n)],
        "users": [k for k, c in users.items() if c >= min(2, n)],
        "ips": [k for k, c in ips.items() if c >= min(2, n)],
        "domains": [k for k, c in domains.items() if c >= min(2, n)],
    }


def _max_severity(alerts: list[dict]) -> str:
    return max((a.get("severity") or "informational" for a in alerts),
               key=lambda s: SEVERITY_RANK.get(s, 0), default="informational")


def _mitre_timeline(alerts: list[dict]) -> None:
    """Línea temporal Altair con las fases MITRE del incidente."""
    rows_t = []
    for a in alerts:
        mitre = a["alert"].get("mitre") or {}
        tactic = mitre.get("tactic") or "Desconocida"
        technique = mitre.get("technique") or ""
        rows_t.append({
            "Hora": a["created_at"][:16],
            "ID": a["alert_id"],
            "Táctica": tactic,
            "Técnica": technique,
        })
    if not rows_t:
        return
    df_t = pd.DataFrame(rows_t)
    tactics_order = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact", "Desconocida",
    ]
    chart = (
        alt.Chart(df_t)
        .mark_circle(size=120)
        .encode(
            x=alt.X("Hora:T", title="Hora"),
            y=alt.Y("Táctica:N", sort=tactics_order, title="Fase MITRE"),
            color=alt.Color("Táctica:N", legend=None),
            tooltip=["Hora", "ID", "Táctica", "Técnica"],
        )
        .properties(height=max(120, len(df_t["Táctica"].unique()) * 35))
    )
    st.altair_chart(chart, use_container_width=True)


for inc, alerts in groups.items():
    example = any("incident_id" in a["example_fields"] for a in alerts)
    max_sev = _max_severity(alerts)
    shared = _shared_entities(alerts)

    # ── Tarjeta de incidente ──────────────────────────────────────────────────
    with st.container(border=True):
        col_title, col_badge = st.columns([4, 1])
        with col_title:
            st.markdown(
                f"#### {inc} · {len(alerts)} alertas"
                + (" &nbsp;<span class='ej'>dato de ejemplo</span>" if example else ""),
                unsafe_allow_html=True,
            )
        with col_badge:
            st.markdown(
                f"Severidad máx.: {ui.severity_badge(max_sev)}",
                unsafe_allow_html=True,
            )

        # Entidades compartidas
        ent_parts = []
        if shared["hosts"]:
            ent_parts.append("**Hosts:** " + ", ".join(f"`{ui.md(h)}`" for h in shared["hosts"]))
        if shared["users"]:
            ent_parts.append("**Usuarios:** " + ", ".join(f"`{ui.md(u)}`" for u in shared["users"]))
        if shared["ips"]:
            ent_parts.append("**IPs:** " + ", ".join(f"`{ui.md(ip)}`" for ip in shared["ips"]))
        if shared["domains"]:
            ent_parts.append("**Dominios:** " + ", ".join(f"`{ui.md(d)}`" for d in shared["domains"]))
        if ent_parts:
            st.markdown("**Entidades compartidas:** " + " · ".join(ent_parts))
        else:
            st.caption("Sin entidades compartidas detectadas.")

        # Tabla resumen de alertas
        st.dataframe(
            pd.DataFrame([{
                "Hora": ui.fmt_time(a["created_at"]),
                "ID": a["alert_id"],
                "Regla": a["rule_name"],
                "Veredicto": ui.VERDICT_LABEL[a["verdict"]],
                "Severidad": ui.SEVERITY_LABEL.get(a.get("severity", ""), a.get("severity", "")),
            } for a in alerts]),
            hide_index=True,
            use_container_width=True,
        )

        # Línea temporal MITRE
        st.markdown("**Línea temporal (fases MITRE)**")
        _mitre_timeline(alerts)
