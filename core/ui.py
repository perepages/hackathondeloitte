"""Piezas visuales comunes y lenguaje claro (dueño: persona A; B las importa).

Idea: alguien que no trabaja en un SOC debe entender cada pantalla. Por eso cada término técnico
tiene aquí su explicación en una frase (VERDICT_HELP, SEVERITY_HELP, describe_query...).

Seguridad: el texto de las alertas lo escribe a veces el atacante. Las funciones que devuelven
HTML solo meten texto NUESTRO; el texto externo pasa siempre por md() o esc().
"""
from __future__ import annotations

import html
import re

import pandas as pd
import streamlit as st

from policy import CRITICALITY_ORDER, SEVERITY_ORDER, base_severity

# ----------------------------------------------------------------------------- paleta
# Validada para daltonismo. No inventar colores fuera de aquí.
VERDICT_COLOR = {"false_positive": "#2a78d6", "true_positive": "#eb6834",
                 "benign_true_positive": "#1baf7a", "needs_more_info": "#eda100"}
VERDICT_ORDER = ["true_positive", "needs_more_info", "benign_true_positive", "false_positive"]
SEVERITY_COLOR = {"critical": "#da291c", "high": "#e0703f", "medium": "#d29a12",
                  "low": "#7f97b2", "informational": "#a7adb7"}
DECISION_COLOR = {"close": "#53565a", "escalate": "#da291c"}
QUERY_ICON = {"ok": "🟢", "not_found": "🟡", "error": "🔴"}
# Interfaz (línea visual tipo Deloitte): negro, grises, azul petróleo interactivo y verde solo de acento
INK, MUTED, LINE, ACCENT = "#000000", "#666666", "#e3e3e3", "#1076a8"
GREEN, GREEN_DARK, GREEN_WASH, SOFT = "#86bc25", "#5c8a1a", "#eef7e0", "#f5f5f5"

# ----------------------------------------------------------------------------- lenguaje claro
VERDICT_LABEL = {"true_positive": "Ataque real", "benign_true_positive": "Actividad autorizada",
                 "false_positive": "Falsa alarma", "needs_more_info": "Falta información"}
VERDICT_HELP = {
    "true_positive": "La alerta es correcta y la actividad es maliciosa o no autorizada.",
    "benign_true_positive": "La alerta es correcta, pero la actividad estaba permitida (un cambio aprobado, una herramienta corporativa…).",
    "false_positive": "La regla saltó, pero no ha pasado nada malo.",
    "needs_more_info": "Con los datos disponibles no se puede concluir: lo tiene que mirar una persona.",
}
VERDICT_TECH = {"true_positive": "true_positive", "benign_true_positive": "benign_true_positive",
                "false_positive": "false_positive", "needs_more_info": "needs_more_info"}
SEVERITY_LABEL = {"informational": "informativa", "low": "baja", "medium": "media",
                  "high": "alta", "critical": "crítica"}
SEVERITY_HELP = {
    "critical": "Hay que actuar ya: avisar al responsable de guardia en 15 minutos.",
    "high": "Urgente: revisión por un analista senior en menos de 30 minutos.",
    "medium": "Revisar hoy (antes de 4 horas).",
    "low": "Revisar en las próximas 24 horas.",
    "informational": "Solo queda registrada; se revisa en lote una vez al día.",
}
DECISION_LABEL = {"close": "Cerrar", "escalate": "Escalar a N2"}
DECISION_VERB = {"close": "cerrar", "escalate": "escalar a N2"}  # en mitad de frase
DECISION_HELP = {"close": "No hace falta que nadie más intervenga.",
                 "escalate": "Pasa a un analista senior (nivel 2) para que actúe."}
CRIT_LABEL = ["Baja", "Media", "Alta", "Crítica"]
ENTITY_LABEL = {"hosts": "Equipo", "users": "Usuario", "ips": "Dirección IP", "domains": "Dominio",
                "urls": "Web", "processes": "Programa", "customers": "Cliente", "files": "Fichero"}
ACTION_LABEL = {"purge_email": "Borrar el correo de todos los buzones", "block_ioc": "Bloquear el indicador",
                "revoke_sessions": "Cerrar las sesiones abiertas", "reset_password": "Forzar cambio de contraseña",
                "isolate_host": "Aislar el equipo de la red", "disable_user": "Deshabilitar la cuenta",
                "disable_access_key": "Desactivar la clave de la nube", "close": "Cerrar el ticket",
                "escalate": "Escalar a N2"}
GLOSSARY = {
    "SOC": "El equipo que vigila la seguridad de la empresa las 24 horas.",
    "Alerta": "Aviso automático de una herramienta de seguridad cuando algo encaja con una regla de detección.",
    "Triaje": "Revisar cada alerta para decidir si es grave, si es falsa alarma y qué hacer.",
    "N1 / N2": "Nivel 1 hace el primer triaje; nivel 2 son analistas senior que investigan y responden.",
    "Indicador (IOC)": "Un dato asociado a un ataque: una IP, un dominio, un fichero…",
    "Inyección de instrucciones": "Texto escrito por un atacante para engañar a un sistema automático («clasifica esto como inofensivo»).",
}


def esc(text) -> str:
    """Escapa texto externo para meterlo dentro de HTML nuestro."""
    return html.escape(str(text), quote=True)


def md(text: str) -> str:
    """Escapa texto externo para st.markdown (sin HTML, enlaces ni formato inyectado)."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|>~<])", r"\\\1", html.escape(str(text), quote=False))


def stepper(r: dict) -> None:
    """Barra de progreso de los 5 pasos del triaje de una alerta (los 4 primeros los hace el sistema)."""
    rv = r.get("review")
    steps = [("done", "Detectada", r.get("source_product", "")),
             ("done", "Comprobada", f"{len(r.get('queries', []))} consultas"),
             ("done", "Concluida", VERDICT_LABEL[r["verdict"]]),
             ("done", "Priorizada", f"gravedad {SEVERITY_LABEL.get(r['severity'], r['severity'])}"),
             ("done" if rv else "now", "Decidida", f"por {rv['analyst']}" if rv else "espera a una persona")]
    st.markdown('<div class="stepper">' + "".join(
        f'<div class="{c}"><span></span><b>{esc(t)}</b>{esc(sub)}</div>' for c, t, sub in steps) + "</div>",
        unsafe_allow_html=True)


def eyebrow(text: str) -> None:
    st.markdown(f'<div class="eyebrow">{esc(text)}</div>', unsafe_allow_html=True)


def empty_state(what: str) -> None:
    """Pantalla sin datos (modo live recién arrancado): explica qué hacer y para la página."""
    st.info(f"Todavía no hay alertas revisadas en esta sesión, así que no hay {what}. "
            "Empieza por **Triaje en directo**: carga alertas y el sistema las revisará.", icon=":material/info:")
    st.page_link("views/directo.py", label="Ir a Triaje en directo", icon=":material/bolt:")
    st.stop()


def llm_md(text: str) -> str:
    """Texto del LLM para st.markdown: los títulos (#) pasan a negrita para no romper la jerarquía de la página."""
    return re.sub(r"^\s*#{1,6}\s*(.+?)\s*#*\s*$", r"**\1**", text or "", flags=re.M)


def fmt_time(iso: str) -> str:
    return iso.replace("T", " ")[:16] + " UTC" if iso else "—"


# ----------------------------------------------------------------------------- estilo
def inject_css() -> None:
    st.markdown(f"""<style>
      .block-container {{ padding-top: 2rem; }}
      h1 {{ font-weight:300 !important; letter-spacing:-.01em; }}
      h1::after {{ content:""; display:block; width:3rem; height:4px; background:{GREEN}; margin-top:.6rem; border-radius:2px; }}
      [data-testid="stVerticalBlockBorderWrapper"] {{ border-radius:12px; }}
      .stepper {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:0; margin:.2rem 0 .4rem; }}
      .stepper div {{ position:relative; padding-top:1.4rem; font-size:.82rem; color:{MUTED}; text-align:center; line-height:1.3; }}
      .stepper div::before {{ content:""; position:absolute; top:.45rem; left:0; right:0; height:3px; background:{LINE}; }}
      .stepper div.done::before {{ background:{GREEN}; }}
      .stepper div span {{ position:absolute; top:0; left:50%; transform:translateX(-50%); width:1.05rem; height:1.05rem;
                            border-radius:50%; background:#fff; border:3px solid {LINE}; }}
      .stepper div.done span {{ border-color:{GREEN}; background:{GREEN}; }}
      .stepper div.now span {{ border-color:{ACCENT}; }}
      .stepper div b {{ display:block; color:{INK}; font-weight:600; }}
      .eyebrow {{ font-size:.78rem; font-weight:600; letter-spacing:.08em; text-transform:uppercase; color:{MUTED}; margin:.2rem 0 .3rem; }}
      .brand {{ font-weight:300; font-size:1.35rem; color:#fff; letter-spacing:-.01em; line-height:1.1; }}
      .brand b {{ font-weight:700; }} .brand i {{ font-style:normal; color:{GREEN}; }}
      .brand-sub {{ color:#a6a6a6; font-size:.78rem; margin-top:.25rem; }}
      .chip {{ display:inline-flex; align-items:center; gap:.35rem; padding:.1rem .6rem; border-radius:999px;
               font-size:.8rem; font-weight:600; white-space:nowrap; line-height:1.6; color:#fff; }}
      .chip.out {{ background:#fff; border:1px solid {LINE}; color:{INK}; font-weight:600; }}
      .dot {{ display:inline-block; width:.6rem; height:.6rem; border-radius:50%; }}
      .ej {{ font-size:.72rem; color:{MUTED}; border:1px dashed #a3abb8; border-radius:4px; padding:0 .35rem;
             margin-left:.4rem; font-weight:500; vertical-align:middle; }}
      .step {{ display:flex; gap:.75rem; align-items:flex-start; margin:.1rem 0 .4rem; }}
      .step .n {{ flex:0 0 1.7rem; height:1.7rem; border-radius:50%; background:{GREEN_WASH}; color:{GREEN_DARK};
                  font-weight:600; display:flex; align-items:center; justify-content:center; font-size:.9rem; }}
      .step .t {{ font-weight:600; font-size:1.02rem; line-height:1.3; }}
      .step .s {{ color:{MUTED}; font-size:.86rem; line-height:1.35; }}
      .q {{ display:grid; grid-template-columns:.9rem 1fr; gap:.15rem .55rem; padding:.45rem .6rem;
            border-radius:.45rem; background:{SOFT}; margin-bottom:.35rem; }}
      .q .d {{ width:.55rem; height:.55rem; border-radius:50%; margin-top:.42rem; }}
      .q .h {{ font-weight:500; }} .q .r {{ grid-column:2; font-size:.88rem; }}
      .q .p {{ grid-column:2; font-family:'IBM Plex Mono',monospace; font-size:.72rem; color:{MUTED}; }}
      .flow {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.75rem; }}
      @media (max-width: 900px) {{ .flow {{ grid-template-columns:1fr 1fr; }} }}
      .flow div {{ background:#fff; border:1px solid {LINE}; border-radius:.6rem; padding:.8rem .9rem; }}
      .flow b {{ display:block; font-size:.98rem; margin-bottom:.2rem; }}
      .flow span {{ color:{MUTED}; font-size:.86rem; line-height:1.35; display:block; }}
      .flow i {{ font-style:normal; color:{GREEN_DARK}; font-weight:600; font-size:.8rem; letter-spacing:.06em; }}
      .big {{ font-size:1.05rem; line-height:1.55; max-width:62rem; }}
      .kcol {{ background:{SOFT}; border:1px solid {LINE}; border-radius:.6rem; padding:.6rem; min-height:12rem; }}
      .kcol.human {{ background:#fdf0ef; border:1px dashed #da291c; }}
      .kcol .kh {{ margin:0 0 .1rem; font-size:.95rem; font-weight:600; display:flex; justify-content:space-between; }}
      .kcol .kh span:last-child {{ background:#fff; border:1px solid {LINE}; border-radius:999px; padding:0 .5rem; font-size:.8rem; }}
      .kcol .hint {{ color:{MUTED}; font-size:.78rem; margin-bottom:.5rem; }}
      .kcard {{ background:#fff; border:1px solid {LINE}; border-left:4px solid #a7adb7; border-radius:.45rem;
                padding:.5rem .6rem; margin-bottom:.45rem; font-size:.86rem; }}
      .kcard.work {{ border-color:{ACCENT}; box-shadow:0 0 0 2px #e7f1f6; }}
      .kcard .kt {{ font-weight:600; line-height:1.3; }}
      .kcard .km {{ color:{MUTED}; font-size:.74rem; }}
      .kcard .kq {{ display:flex; gap:.4rem; font-size:.78rem; margin-top:.2rem; line-height:1.3; }}
      .kcard .kq span:first-child {{ flex:0 0 .5rem; height:.5rem; border-radius:50%; margin-top:.3rem; }}
      .kcard .kc {{ margin-top:.3rem; display:flex; gap:.3rem; flex-wrap:wrap; }}
      .muted {{ color:{MUTED}; }}
    </style>""", unsafe_allow_html=True)


def verdict_badge(v: str) -> str:
    return (f'<span class="chip out" title="{esc(VERDICT_HELP[v])}"><span class="dot" '
            f'style="background:{VERDICT_COLOR[v]}"></span>{VERDICT_LABEL[v]}</span>')


def severity_badge(s: str) -> str:
    return (f'<span class="chip" style="background:{SEVERITY_COLOR[s]}" title="{esc(SEVERITY_HELP[s])}">'
            f'gravedad {SEVERITY_LABEL[s]}</span>')


def decision_badge(d: str) -> str:
    return f'<span class="chip" style="background:{DECISION_COLOR[d]}">{DECISION_LABEL[d]}</span>'


def example_tag(view: dict, field: str) -> str:
    """Marca visible cuando el valor viene de las reglas de ejemplo y no del back."""
    return ('<span class="ej" title="Valor de prueba: el back todavía no lo calcula">dato de ejemplo</span>'
            if field in view.get("example_fields", []) else "")


def step(n: int | str, title: str, subtitle: str = "", extra_html: str = "") -> None:
    """Cabecera numerada de un paso, con una frase que explica para qué sirve."""
    st.markdown(f'<div class="step"><div class="n">{n}</div><div><div class="t">{esc(title)} {extra_html}</div>'
                f'<div class="s">{esc(subtitle)}</div></div></div>', unsafe_allow_html=True)


# ----------------------------------------------------------------------------- consultas
def describe_query(q: dict) -> str:
    """Qué ha preguntado el sistema, dicho para alguien de fuera."""
    path = str(q.get("path", ""))
    key = path.rsplit("/", 1)[-1]
    if path.startswith("/assets/"):
        return f"Ficha del equipo {key} en el inventario de la empresa"
    if path.startswith("/users/"):
        return f"Datos del empleado {key}"
    if path.startswith("/intel/"):
        return f"Reputación de {key} en inteligencia de amenazas"
    if path.startswith("/sandbox/"):
        return "Análisis del fichero en un entorno aislado (sandbox)"
    if path == "/changes":
        target = (q.get("params") or {}).get("q", "")
        return f"¿Hay un cambio aprobado que lo explique?{' (' + target + ')' if target else ''}"
    if path.startswith("/logs/"):
        return f"Registros de actividad de {path.split('/')[2]} en las 24 h de antes y después"
    return path


def query_list(queries: list[dict], limit: int | None = None) -> None:
    """Lista de comprobaciones: qué preguntó, qué encontró y la llamada técnica en pequeño."""
    if not queries:
        st.caption("Ninguna consulta: la alerta no trae datos que se puedan comprobar.")
        return
    colors = {"ok": "#1a8a5f", "not_found": "#d29a12", "error": "#c62f2f"}
    out = []
    for q in queries[:limit]:
        params = " ".join(f"{k}={v}" for k, v in (q.get("params") or {}).items() if v)
        out.append(f'<div class="q"><span class="d" style="background:{colors.get(q.get("status"), "#999")}"></span>'
                   f'<span class="h">{esc(describe_query(q))}</span>'
                   f'<span class="r">{esc(q.get("summary", ""))}</span>'
                   f'<span class="p">{esc(q.get("method", "GET"))} {esc(q.get("path", ""))} {esc(params)}</span></div>')
    st.markdown("".join(out), unsafe_allow_html=True)


# ----------------------------------------------------------------------------- tablas
def severity_matrix(rule_sev: str, criticality: str | None) -> "pd.io.formats.style.Styler":
    """Matriz §2 de la política con la celda aplicada resaltada."""
    rows = {SEVERITY_LABEL[s]: [SEVERITY_LABEL[base_severity(s, c)] for c in CRITICALITY_ORDER] for s in SEVERITY_ORDER}
    df = pd.DataFrame.from_dict(rows, orient="index", columns=CRIT_LABEL)
    df.index.name = "Regla ↓ · Equipo →"
    col = next((i for i, c in enumerate(CRITICALITY_ORDER)
                if criticality and criticality.lower().replace("í", "i") == c), None)

    def hl(data):
        out = pd.DataFrame("color: #8a93a3", index=data.index, columns=data.columns)
        if col is not None and rule_sev in SEVERITY_LABEL:
            out.iloc[SEVERITY_ORDER.index(rule_sev), col] = f"background-color: {ACCENT}; color: #fff; font-weight: 700"
        return out

    return df.style.apply(hl, axis=None)


def style_queue(df: pd.DataFrame) -> "pd.io.formats.style.Styler":
    """Colorea la columna «Gravedad» (o «Severidad») de una tabla de alertas."""
    col = "Gravedad" if "Gravedad" in df.columns else "Severidad"
    by_label = {SEVERITY_LABEL[k]: v for k, v in SEVERITY_COLOR.items()}

    def cell(v):
        c = by_label.get(v)
        return f"background-color: {c}; color: #ffffff; font-weight: 600" if c else ""

    return df.style.map(cell, subset=[col])


def is_ot(view: dict) -> bool:
    """La política prohíbe al SOC actuar sobre la red OT: solo se escala a Operaciones."""
    return any(c["kind"] == "asset" and c["data"].get("zone") == "LOGISTICS-OT" for c in view.get("contexts", []))


def live_card(view: dict, state: str, calls: list[dict] | None = None) -> str:
    """Tarjeta del kanban del directo. state: 'in' | 'work' | 'close' | 'esc'. Solo HTML nuestro + texto escapado."""
    resolved = state in ("close", "esc")
    border = SEVERITY_COLOR.get(view.get("severity"), "#a7adb7") if resolved else "#a7adb7"
    body = ""
    if state == "work":
        colors = {"ok": "#1a8a5f", "not_found": "#d29a12", "error": "#c62f2f"}
        body = "".join(f'<div class="kq"><span style="background:{colors.get(c.get("status"), "#999")}"></span>'
                       f'<span>{esc(describe_query(c))}</span></div>' for c in (calls or []))
        body += '<div class="kq muted"><span></span><span>comprobando…</span></div>'
    if resolved:
        body = f'<div class="kc">{verdict_badge(view["verdict"])}{severity_badge(view["severity"])}</div>'
    return (f'<div class="kcard{" work" if state == "work" else ""}" style="border-left-color:{border}">'
            f'<div class="kt">{esc(view.get("rule_name", ""))}</div>'
            f'<div class="km">{esc(view.get("source_product", ""))} · {esc(fmt_time(view.get("created_at", ""))[5:16])}</div>'
            f'{body}</div>')


def live_column(title: str, hint: str, cards: list[str], human: bool = False) -> str:
    return (f'<div class="kcol{" human" if human else ""}"><div class="kh"><span>{esc(title)}</span><span>{len(cards)}</span></div>'
            f'<div class="hint">{esc(hint)}</div>{"".join(cards)}</div>')


def entities_table(alert: dict) -> pd.DataFrame:
    rows = []
    for k, vals in (alert.get("entities") or {}).items():
        for v in vals or []:
            val = (v.get("hostname") or v.get("upn") or v.get("name") or v.get("customer_id") or str(v)) \
                if isinstance(v, dict) else str(v)
            rows.append((ENTITY_LABEL.get(k, k), val))
    return pd.DataFrame(rows, columns=["Qué", "Cuál"])
