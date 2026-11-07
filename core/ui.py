"""Piezas visuales comunes (dueño: persona A; B las importa para el panel y el directo).

Regla de seguridad: el texto de las alertas lo escribe a veces el atacante. Las funciones que
devuelven HTML (`*_badge`) solo meten texto NUESTRO. Para texto de la alerta usad st.text,
st.code, st.dataframe o md() (que escapa el markdown).
"""
from __future__ import annotations

import html
import re

import pandas as pd
import streamlit as st

from policy import CRITICALITY_ORDER, SEVERITY_ORDER, base_severity

# --- paleta (validada para daltonismo; no inventar colores fuera de aquí) -----------------
VERDICT_COLOR = {"false_positive": "#2a78d6", "true_positive": "#eb6834",
                 "benign_true_positive": "#1baf7a", "needs_more_info": "#eda100"}
VERDICT_ORDER = ["false_positive", "true_positive", "benign_true_positive", "needs_more_info"]
SEVERITY_COLOR = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#e0a514",
                  "low": "#7f97b2", "informational": "#a7adb7"}
DECISION_COLOR = {"close": "#2a78d6", "escalate": "#eb6834"}
QUERY_ICON = {"ok": "🟢", "not_found": "🟡", "error": "🔴"}

VERDICT_LABEL = {"true_positive": "Verdadero positivo", "benign_true_positive": "Benigno autorizado",
                 "false_positive": "Falso positivo", "needs_more_info": "Falta información"}
SEVERITY_LABEL = {"informational": "informativa", "low": "baja", "medium": "media",
                  "high": "alta", "critical": "crítica"}
DECISION_LABEL = {"close": "Cerrar", "escalate": "Escalar a N2"}
CRIT_LABEL = ["Baja", "Media", "Alta", "Crítica"]
ACTION_LABEL = {"purge_email": "Purgar correo", "block_ioc": "Bloquear IOC", "revoke_sessions": "Revocar sesiones",
                "reset_password": "Forzar cambio de contraseña", "isolate_host": "Aislar equipo",
                "disable_user": "Deshabilitar cuenta", "disable_access_key": "Desactivar clave cloud",
                "close": "Cerrar ticket", "escalate": "Escalar a N2"}


def inject_css() -> None:
    st.markdown("""<style>
      .chip{display:inline-block;padding:1px 9px;border-radius:999px;font-size:.8rem;font-weight:600;
            color:#fff;white-space:nowrap;line-height:1.6}
      .chip.out{background:transparent;border:1px solid rgba(128,128,128,.4);color:inherit;font-weight:500}
      .dot{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.35rem}
      .ej{font-size:.75rem;color:#8a8f99;border:1px dashed #8a8f99;border-radius:4px;padding:0 5px;margin-left:6px}
    </style>""", unsafe_allow_html=True)


def verdict_badge(v: str) -> str:
    return f'<span class="chip out"><span class="dot" style="background:{VERDICT_COLOR[v]}"></span>{VERDICT_LABEL[v]}</span>'


def severity_badge(s: str) -> str:
    return f'<span class="chip" style="background:{SEVERITY_COLOR[s]}">{SEVERITY_LABEL[s]}</span>'


def decision_badge(d: str) -> str:
    return f'<span class="chip" style="background:{DECISION_COLOR[d]}">{DECISION_LABEL[d]}</span>'


def example_tag(view: dict, field: str) -> str:
    """Marca visible cuando el valor viene de las reglas de ejemplo y no del back."""
    return '<span class="ej">dato de ejemplo</span>' if field in view.get("example_fields", []) else ""


def md(text: str) -> str:
    """Escapa texto externo para st.markdown (sin HTML, sin enlaces ni formato inyectado)."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|>~<])", r"\\\1", html.escape(str(text), quote=False))


def severity_matrix(rule_sev: str, criticality: str | None) -> "pd.io.formats.style.Styler":
    """Matriz §2 de la política con la celda aplicada resaltada."""
    rows = {SEVERITY_LABEL[s]: [SEVERITY_LABEL[base_severity(s, c)] for c in CRITICALITY_ORDER] for s in SEVERITY_ORDER}
    df = pd.DataFrame.from_dict(rows, orient="index", columns=CRIT_LABEL)
    df.index.name = "Regla ↓ · Activo →"
    col = next((i for i, c in enumerate(CRITICALITY_ORDER)
                if criticality and criticality.lower().replace("í", "i") == c), None)

    def hl(data):
        out = pd.DataFrame("", index=data.index, columns=data.columns)
        if col is not None and rule_sev in SEVERITY_LABEL:
            out.iloc[SEVERITY_ORDER.index(rule_sev), col] = "background-color: #2a78d6; color: #ffffff; font-weight: 700"
        return out

    return df.style.apply(hl, axis=None)


def query_list(queries: list[dict]) -> None:
    """Lista de consultas a la API con su resultado en una frase."""
    if not queries:
        st.caption("Ninguna consulta: la alerta no trae entidades consultables.")
    for q in queries:
        params = " ".join(f"{k}={v}" for k, v in (q.get("params") or {}).items() if v)
        path = str(q["path"]).replace("`", "")  # dentro de `código` no hace falta escapar
        st.markdown(f"{QUERY_ICON.get(q['status'], '⚪')} `{q.get('method', 'GET')} {path}`"
                    + (f" <small>{md(params)}</small>" if params else "")
                    + f"  \n&nbsp;&nbsp;&nbsp;&nbsp;{md(q.get('summary', ''))}", unsafe_allow_html=True)


def fmt_time(iso: str) -> str:
    return iso.replace("T", " ")[:16] + " UTC" if iso else "—"
