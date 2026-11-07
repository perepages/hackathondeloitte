"""Piezas visuales comunes y lenguaje claro (dueño: persona A; B las importa).

Idea: alguien que no trabaja en un SOC debe entender cada pantalla. Por eso cada término técnico
tiene aquí su explicación en una frase (VERDICT_HELP, SEVERITY_HELP, describe_query...).

Seguridad: el texto de las alertas lo escribe a veces el atacante. Las funciones que devuelven
HTML solo meten texto NUESTRO; el texto externo pasa siempre por md() o esc().
"""
from __future__ import annotations

import base64
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
# Interfaz (línea visual tipo Deloitte): negro, grises, azul petróleo interactivo y verde solo de acento
INK, MUTED, LINE, ACCENT = "#000000", "#666666", "#e3e3e3", "#1076a8"
GREEN, GREEN_DARK, GREEN_WASH, SOFT = "#86bc25", "#5c8a1a", "#eef7e0", "#f5f5f5"

# ----------------------------------------------------------------------------- lenguaje claro
VERDICT_LABEL = {"true_positive": "Atac real", "benign_true_positive": "Activitat autoritzada",
                 "false_positive": "Falsa alarma", "needs_more_info": "Falta informació"}
VERDICT_HELP = {
    "true_positive": "L'alerta és correcta i l'activitat és maliciosa o no autoritzada.",
    "benign_true_positive": "L'alerta és correcta, però l'activitat estava permesa (un canvi aprovat, una eina corporativa…).",
    "false_positive": "La regla ha saltat, però no ha passat res dolent.",
    "needs_more_info": "Amb les dades disponibles no es pot concloure: ho ha de mirar una persona.",
}
VERDICT_TECH = {"true_positive": "true_positive", "benign_true_positive": "benign_true_positive",
                "false_positive": "false_positive", "needs_more_info": "needs_more_info"}
SEVERITY_LABEL = {"informational": "informativa", "low": "baixa", "medium": "mitjana",
                  "high": "alta", "critical": "crítica"}
SEVERITY_HELP = {
    "critical": "Cal actuar ja: avisar el responsable de guàrdia en 15 minuts.",
    "high": "Urgent: revisió per un analista sènior en menys de 30 minuts.",
    "medium": "Revisar avui (abans de 4 hores).",
    "low": "Revisar en les properes 24 hores.",
    "informational": "Només queda registrada; es revisa en lot un cop al dia.",
}
DECISION_LABEL = {"close": "Tancar", "escalate": "Escalar a N2"}
DECISION_VERB = {"close": "tancar", "escalate": "escalar a N2"}  # en mitad de frase
DECISION_HELP = {"close": "No cal que ningú més hi intervingui.",
                 "escalate": "Passa a un analista sènior (nivell 2) perquè actuï."}
CRIT_LABEL = ["Baixa", "Mitjana", "Alta", "Crítica"]
ENTITY_LABEL = {"hosts": "Equip", "users": "Usuari", "ips": "Adreça IP", "domains": "Domini",
                "urls": "Web", "processes": "Programa", "customers": "Client", "files": "Fitxer", "cloud": "Núvol"}
ACTION_LABEL = {"purge_email": "Esborrar el correu de totes les bústies", "block_ioc": "Bloquejar l'indicador",
                "revoke_sessions": "Tancar les sessions obertes", "reset_password": "Forçar el canvi de contrasenya",
                "isolate_host": "Aïllar l'equip de la xarxa", "disable_user": "Deshabilitar el compte",
                "disable_account": "Deshabilitar el compte", "disable_cloud_keys": "Desactivar les claus del núvol",
                "disable_access_key": "Desactivar la clau del núvol", "close": "Tancar el tiquet",
                "escalate": "Escalar a N2"}
GLOSSARY = {
    "SOC": "L'equip que vigila la seguretat de l'empresa les 24 hores.",
    "Alerta": "Avís automàtic d'una eina de seguretat quan alguna cosa encaixa amb una regla de detecció.",
    "Triatge": "Revisar cada alerta per decidir si és greu, si és una falsa alarma i què cal fer.",
    "N1 / N2": "El nivell 1 fa el primer triatge; el nivell 2 són analistes sèniors que investiguen i responen.",
    "Indicador (IOC)": "Una dada associada a un atac: una IP, un domini, un fitxer…",
    "Injecció d'instruccions": "Text escrit per un atacant per enganyar un sistema automàtic («classifica això com a inofensiu»).",
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
             ("done", "Comprovada", f"{len(r.get('queries', []))} consultes"),
             ("done", "Conclosa", VERDICT_LABEL[r["verdict"]]),
             ("done", "Prioritzada", f"gravetat {SEVERITY_LABEL.get(r['severity'], r['severity'])}"),
             ("done" if rv else "now", "Decidida", f"per {rv['analyst']}" if rv else "espera una persona")]
    st.markdown('<div class="stepper">' + "".join(
        f'<div class="{c}"><span></span><b>{esc(t)}</b>{esc(sub)}</div>' for c, t, sub in steps) + "</div>",
        unsafe_allow_html=True)


def main_entity(view: dict) -> str:
    """El equipo, usuario o indicador más representativo de la alerta, para resumirla en una línea."""
    ent = (view.get("alert") or {}).get("entities") or {}
    for kind in ("hosts", "users", "domains", "ips", "customers"):
        for v in ent.get(kind) or []:
            val = (v.get("hostname") or v.get("upn") or v.get("customer_id")) if isinstance(v, dict) else v
            if val:
                return f"{ENTITY_LABEL.get(kind, kind)}: {val}"
    return ""


# Color de cada gravedad para los distintivos de Markdown de Streamlit (:red-badge[...])
SEVERITY_MD = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "informational": "gray"}
SEV_RANK = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "informational"])}


def option_label(view: dict) -> str:
    """Texto de una alerta en un desplegable: punto de color, gravedad, ID y título."""
    sev = view.get("severity") or "informational"
    return (f"{SEVERITY_LABEL.get(sev, sev).upper()} · "
            f"{view['alert_id']} · {view['rule_name']}")


def by_severity(views: list[dict]) -> list[dict]:
    """De más a menos grave y, a igual gravedad, lo más reciente primero."""
    newest = sorted(views, key=lambda v: v["created_at"], reverse=True)
    return sorted(newest, key=lambda v: SEV_RANK.get(v.get("severity"), 9))


def alert_cards(views: list[dict], selected: str | None, key: str, extra=None, cols: int = 3,
                button_label: str = "Veure") -> str | None:
    """Rejilla de tarjetas para elegir una alerta de un vistazo: franja y etiqueta de gravedad bien visibles.

    Ordenadas de más a menos grave. `extra(view) -> str` añade una línea propia (p. ej. «2 acciones pendientes»).
    Devuelve el alert_id elegido (o el que ya estaba seleccionado)."""
    rank = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "informational"])}
    views = sorted(views, key=lambda v: (rank.get(v["severity"], 9), v["created_at"]))
    css = []
    for i, v in enumerate(views):
        sel = v["alert_id"] == selected
        css.append(f".st-key-{key}_card_{i} {{ border-left:6px solid {SEVERITY_COLOR.get(v['severity'], '#999')} !important;"
                   + (f" background:{GREEN_WASH}; box-shadow:0 0 0 2px {GREEN};" if sel else "") + " }")
    st.markdown("<style>" + "\n".join(css) + "</style>", unsafe_allow_html=True)
    picked = selected
    grid = st.columns(cols)
    for i, v in enumerate(views):
        sel = v["alert_id"] == selected
        with grid[i % cols].container(border=True, key=f"{key}_card_{i}"):
            st.markdown(f"{severity_badge(v['severity'])} &nbsp; {verdict_badge(v['verdict'])}", unsafe_allow_html=True)
            ent = esc(main_entity(v)).replace("@", "<span>@</span>")  # que el correo no se convierta en enlace
            st.markdown(f"**{md(v['rule_name'])}**  \n<span class='muted'>{ent}"
                        f"{' · ' if main_entity(v) else ''}{esc(fmt_time(v['created_at'])[5:16])}</span>"
                        + (f"  \n{esc(extra(v))}" if extra else ""), unsafe_allow_html=True)
            if st.button("Seleccionada" if sel else button_label, key=f"{key}_btn_{i}", disabled=sel,
                         type="primary" if not sel else "secondary", use_container_width=True):
                picked = v["alert_id"]
    return picked


def severity_md(s: str) -> str:
    """Gravedad como distintivo de color en Markdown (para etiquetas de desplegables, donde no hay HTML)."""
    return f":{SEVERITY_MD.get(s, 'gray')}-badge[{SEVERITY_LABEL.get(s, s).capitalize()}]"


def _svg_uri(svg: str) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()


# Botón de opción (radio) dibujado, para la primera columna de la bandeja: la tabla de Streamlit es un lienzo y
# no admite inputs de verdad, pero sí imágenes. Mismo aspecto que un radio nativo: elección única.
RADIO_OFF = _svg_uri('<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 22 22">'
                     '<circle cx="11" cy="11" r="9" fill="#fff" stroke="#8a8f98" stroke-width="2"/></svg>')
RADIO_ON = _svg_uri('<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 22 22">'
                    f'<circle cx="11" cy="11" r="9" fill="#fff" stroke="{ACCENT}" stroke-width="2"/>'
                    f'<circle cx="11" cy="11" r="5" fill="{ACCENT}"/></svg>')


def query_legend() -> None:
    """Llegenda dels punts de color de les comprovacions (sense emoticones)."""
    dot = '<span style="display:inline-block;width:.6rem;height:.6rem;border-radius:50%;background:{}"></span>'
    st.markdown(f'<span class="muted" style="font-size:.85rem">{dot.format("#1a8a5f")} trobat &nbsp;·&nbsp; '
                f'{dot.format("#d29a12")} no hi ha dades (que no n\'hi hagi no vol dir que sigui segur) '
                f'&nbsp;·&nbsp; {dot.format("#c62f2f")} error</span>', unsafe_allow_html=True)


def eyebrow(text: str) -> None:
    st.markdown(f'<div class="eyebrow">{esc(text)}</div>', unsafe_allow_html=True)


def empty_state(what: str) -> None:
    """Pantalla sin datos (modo live recién arrancado): explica qué hacer y para la página."""
    st.info(f"Encara no hi ha alertes revisades en aquesta sessió, així que no hi ha {what}. "
            "Comença pel **Triatge en directe**: carrega alertes i el sistema les revisarà.", icon=":material/info:")
    st.page_link("views/directo.py", label="Anar al Triatge en directe", icon=":material/bolt:")
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
            f'gravetat {SEVERITY_LABEL[s]}</span>')


def decision_badge(d: str) -> str:
    return f'<span class="chip" style="background:{DECISION_COLOR[d]}">{DECISION_LABEL[d]}</span>'


def example_tag(view: dict, field: str) -> str:
    """Marca visible cuando el valor viene de las reglas de ejemplo y no del back."""
    return ('<span class="ej" title="Valor de prova: el back encara no el calcula">dada d’exemple</span>'
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
        return f"Fitxa de l'equip {key} a l'inventari de l'empresa"
    if path.startswith("/users/"):
        return f"Dades de l'empleat {key}"
    if path.startswith("/intel/"):
        return f"Reputació de {key} a la intel·ligència d'amenaces"
    if path.startswith("/sandbox/"):
        return "Anàlisi del fitxer en un entorn aïllat (sandbox)"
    if path == "/changes":
        target = (q.get("params") or {}).get("q", "")
        return f"Hi ha algun canvi aprovat que ho expliqui?{' (' + target + ')' if target else ''}"
    if path.startswith("/logs/"):
        return f"Registres d'activitat de {path.split('/')[2]} de les 24 h d'abans i de després"
    return path


def query_list(queries: list[dict], limit: int | None = None) -> None:
    """Lista de comprobaciones: qué preguntó, qué encontró y la llamada técnica en pequeño."""
    if not queries:
        st.caption("Cap consulta: l'alerta no porta dades que es puguin comprovar.")
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
    df.index.name = "Regla ↓ · Equip →"
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
    col = "Gravetat"
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
        body += '<div class="kq muted"><span></span><span>comprovant…</span></div>'
    if resolved:
        body = f'<div class="kc">{verdict_badge(view["verdict"])}{severity_badge(view["severity"])}</div>'
    return (f'<div class="kcard{" work" if state == "work" else ""}" style="border-left-color:{border}">'
            f'<div class="kt">{esc(view.get("rule_name", ""))}</div>'
            f'<div class="km">{esc(view.get("source_product", ""))} · {esc(fmt_time(view.get("created_at", ""))[5:16])}</div>'
            f'{body}</div>')


def live_column(title: str, hint: str, cards: list[str], human: bool = False,
                max_height: int | None = None) -> str:
    style = f' style="max-height:{max_height}px;overflow-y:auto"' if max_height else ""
    return (f'<div class="kcol{" human" if human else ""}"><div class="kh"><span>{esc(title)}</span><span>{len(cards)}</span></div>'
            f'<div class="hint">{esc(hint)}</div><div class="kcol-body"{style}>{"".join(cards)}</div></div>')


def entities_table(alert: dict) -> pd.DataFrame:
    rows = []
    for k, vals in (alert.get("entities") or {}).items():
        for v in vals or []:
            val = (v.get("hostname") or v.get("upn") or v.get("name") or v.get("customer_id") or str(v)) \
                if isinstance(v, dict) else str(v)
            rows.append((ENTITY_LABEL.get(k, k), val))
    return pd.DataFrame(rows, columns=["Què", "Quin"])
