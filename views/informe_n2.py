"""Informe para N2: el ticket en el formato de Deloitte (01_contexto/ticket_salida.schema.json). Textos en catalán.

Dueño: PERSONA A. Arriba el informe legible para una persona; abajo el JSON validado y descargable.
Si la alerta forma parte de un incidente (incidents.py), el informe es el del INCIDENTE entero: política §6, «varias
alertas sobre la misma intrusión se documentan en un único ticket con todos los alert_ids».
"""
import json
import os

import pandas as pd
import streamlit as st

from core import data, ui

SCHEMA = os.path.join(data.ROOT, "..", "DTT-UAB-The-Hack", "01_contexto", "ticket_salida.schema.json")


# Lo que cuenta de un registro, en este orden (el formato de Deloitte pide «finding»: qué muestra, no solo su tipo)
FINDING_KEYS = ("event_type", "event", "eventName", "action", "result", "status", "process_name", "command_line",
                "url", "domain", "query", "response_summary", "dest_ip", "dst_ip", "dst", "src_ip", "src",
                "sourceIPAddress", "sender", "subject", "target", "user", "upn", "customer_id", "hostname",
                "bytes_out", "bytes", "app", "country")


def finding(e: dict) -> str:
    """Una línea con lo que muestra un registro: tipo y los datos que importan (sin el texto libre largo)."""
    parts = []
    for k in FINDING_KEYS:
        v = e.get(k)
        if v in (None, "", [], {}):
            continue
        v = str(v).replace("\n", " ")
        parts.append(v[:70] + ("…" if len(v) > 70 else "") if k == "event_type" else f"{k}={v[:70]}")
        if len(parts) == 5:
            break
    return " · ".join(parts)[:240] or "registre relacionat"


def build_ticket(r: dict) -> dict:
    """Contrato del front -> ticket de Deloitte. La decisión de la persona, si existe, manda sobre la propuesta."""
    ctx = r["contexts"]
    assets = [c["data"] for c in ctx if c["kind"] == "asset"]
    decision = (r.get("review") or {}).get("decision") or r["decision"]
    title = r["title"] if r["title"] and "title" not in r["example_fields"] else \
        f"{r['rule_name']}: {ui.VERDICT_LABEL[r['verdict']].lower()}"
    return {
        "ticket_id": f"TKT-{r['alert_id']}",
        "alert_ids": (r.get("group") or {}).get("alert_ids") or [r["alert_id"]],  # política §6: un ticket per esdeveniment
        "title": title,
        "verdict": r["verdict"],
        "confidence": float(r["confidence"] or 0.0),
        "severity": r["severity"],
        "severity_rationale": r["severity_rationale"],
        "affected": {
            "users": [c["key"] for c in ctx if c["kind"] == "user"],
            "hosts": [a.get("hostname") for a in assets],
            "business_services": sorted({a.get("business_service") for a in assets if a.get("business_service")}),
            "customers": [c.get("customer_id") for c in (r["alert"].get("entities") or {}).get("customers", [])],
        },
        "summary": r["summary"] or r["justification"] or r["severity_rationale"],
        "evidence": [{"source": e.get("_source", ""), "event_id": e.get("event_id", ""), "finding": finding(e)}
                     for e in r["related_logs"][:15]],
        "enrichment": [{"indicator": q["path"].rsplit("/", 1)[-1], "type": "intel", "source": "TIP + GeoIP",
                        "result": q["summary"]} for q in r["queries"] if q["path"].startswith("/intel/")]
                      + [{"indicator": c["key"], "type": "sha256", "source": "Sandbox",
                          "result": f"veredicte {c['data'].get('verdict', '?')}, puntuació {c['data'].get('score', '?')}"
                                    + (f", família {c['data']['family']}" if c["data"].get("family") else "")}
                         for c in ctx if c["kind"] == "sandbox"],
        "mitre": [m] if (m := (r["alert"].get("mitre") or {}).get("technique_id")) else [],
        "recommended_actions": r["recommended_actions"],
        "executed_actions": [],
        "escalation": {"escalate": decision == "escalate", "to": "N2" if decision == "escalate" else "",
                       "reason": r["justification"] if decision == "escalate" else ""},
        "open_questions": r["open_questions"],
    }


def _union(items: list, key=lambda x: str(x)) -> list:
    out, seen = [], set()
    for x in items:
        k = key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def build_incident_ticket(inc: dict, members: list[dict]) -> dict:
    """Un ticket de Deloitte para todo el incidente: une los de sus alertas (en orden de llegada)."""
    tickets = [build_ticket(r) for r in members]
    attack = [t for t in tickets if t["verdict"] == "true_positive"] or tickets
    escalate = any(t["escalation"]["escalate"] for t in tickets) or inc["decision"] == "escalate"
    timeline = " → ".join(f"{r['created_at'][5:16].replace('T', ' ')} {r['rule_name']}" for r in members)
    affected = {k: _union([v for t in tickets for v in t["affected"][k] if v]) for k in tickets[0]["affected"]}
    return {
        "ticket_id": f"TKT-{inc['incident_id']}",
        "alert_ids": inc["alert_ids"],
        "title": inc["title"],
        "verdict": inc["verdict"],
        "confidence": max(t["confidence"] for t in attack),
        "severity": inc["severity"],
        "severity_rationale": (f"La gravetat més alta de les {inc['count']} alertes (la matriu §2 s'aplica alerta per "
                               "alerta). " + " ".join(t["severity_rationale"] for t in attack
                                                      if t["severity"] == inc["severity"])[:600]),
        "affected": affected,
        "summary": (f"{inc['count']} alertes del mateix atac, del {inc['first_seen'][:16].replace('T', ' ')} al "
                    f"{inc['last_seen'][:16].replace('T', ' ')}. Comparteixen: "
                    + ", ".join(f"{x['label']} " + (x["value"].upper() if x["kind"] == "equip" and
                                                       not x["value"].replace(".", "").isdigit() else x["value"][:60])
                                for x in inc["shared"][:6])
                    + f". Seqüència: {timeline}."),
        "evidence": _union([e for t in tickets for e in t["evidence"]], key=lambda e: e.get("event_id") or str(e)),
        "enrichment": _union([e for t in tickets for e in t["enrichment"]], key=lambda e: e["indicator"]),
        "mitre": _union([m for t in tickets for m in t["mitre"]]),
        "recommended_actions": _union([a for t in tickets for a in t["recommended_actions"]],
                                      key=lambda a: (a["action"], a["target"])),
        "executed_actions": [],
        "escalation": {"escalate": escalate, "to": "N2" if escalate else "",
                       "reason": "; ".join(inc["reasons"]) if escalate else ""},
        "open_questions": _union([q for t in tickets for q in t["open_questions"]]),
    }


def validate(ticket: dict) -> str | None:
    """None si cumple el esquema; el error si no; 'sin-esquema' si no está el dataset al lado."""
    try:
        import jsonschema
        with open(SCHEMA, encoding="utf-8") as f:
            jsonschema.validate(ticket, json.load(f))
        return None
    except FileNotFoundError:
        return "sin-esquema"
    except Exception as exc:  # jsonschema.ValidationError
        return str(exc).splitlines()[0]


rows = data.load_results()
ids = [r["alert_id"] for r in ui.by_severity(rows)]  # en el desplegable, de más a menos grave
if not rows:
    st.title("Informe per a N2")
    ui.empty_state("informes")
current = st.session_state.get("selected_alert")
if current not in ids:
    current = next((r["alert_id"] for r in rows if r["decision"] == "escalate"), ids[0])

st.title("Informe per a N2")
st.markdown('<p class="muted">El que rep l\'analista sènior quan s\'escala una alerta: què ha passat, a qui '
            "afecta, en què es basa la conclusió i què es recomana fer. Segueix el format oficial de Deloitte.</p>",
            unsafe_allow_html=True)
alert_id = st.selectbox("Alerta", ids, index=ids.index(current), key="ticket_alert",
                        format_func=lambda i: ui.option_label(data.get_result(i)),
                        help="Ordenades de més a menys greu: 🔴 crítica · 🟠 alta · 🟡 mitjana · 🔵 baixa · ⚪ informativa")
st.session_state["selected_alert"] = alert_id
r = data.get_result(alert_id)
inc, members = data.get_incident(r["incident_id"]) if r.get("incident_id") else (None, [])
t = build_incident_ticket(inc, members) if inc else build_ticket(r)
rv = r["review"] if not inc else None
if inc:
    st.info(f"**Aquesta alerta forma part de l'incident {inc['incident_id']}** ({inc['count']} alertes del mateix "
            "atac). Segons la política del SOC (§6) es documenta en **un sol informe** amb totes les alertes: és el "
            "que veus a sota.", icon=":material/hub:")
    if st.button("Veure l'incident", key="ticket_to_incident", icon=":material/hub:"):
        st.session_state["focus_incident"] = inc["incident_id"]
        st.switch_page("views/incidents.py")

# ---------------------------------------------------------------------------- cabecera
with st.container(border=True):
    st.markdown(f"{ui.severity_badge(t['severity'])} &nbsp; {ui.verdict_badge(t['verdict'])}"
                f"{ui.example_tag(r, 'verdict')} &nbsp; <span class='muted'>{ui.esc(t['ticket_id'])}</span>",
                unsafe_allow_html=True)
    st.subheader(t["title"], anchor=False)
    esc = t["escalation"]["escalate"]
    who = (f"decidit per {rv['analyst']}" if rv else "proposta del sistema, encara sense revisar per una persona")
    (st.warning if esc else st.info)(("**S'escala a N2** · " if esc else "**Es tanca** · ") + who)
    st.markdown(f"**Què ha passat.** {ui.md(t['summary'])}")
    m = st.columns(3)
    m[0].metric("Seguretat de la conclusió", f"{round(t['confidence'] * 100)} %" if r["confidence"] is not None else "—")
    m[1].metric("Gravetat", ui.SEVERITY_LABEL[t["severity"]].capitalize(), help=ui.SEVERITY_HELP[t["severity"]])
    m[2].metric("Tècnica d'atac (MITRE)", ", ".join(t["mitre"][:4]) + (" …" if len(t["mitre"]) > 4 else "") or "—")
    if inc:
        st.caption(f"Alertes de l'informe: {', '.join(t['alert_ids'])}")

# ---------------------------------------------------------------------------- cuerpo
c1, c2 = st.columns(2, gap="large")
with c1:
    st.markdown("**A qui afecta**")
    aff = t["affected"]
    st.dataframe(pd.DataFrame([("Persones", ", ".join(aff["users"]) or "—"), ("Equips", ", ".join(aff["hosts"]) or "—"),
                               ("Serveis de negoci", ", ".join(aff["business_services"]) or "—"),
                               ("Clients", ", ".join(aff["customers"]) or "—")], columns=["Què", "Quin"]),
                 hide_index=True, use_container_width=True)
    st.markdown("**Què se sap dels indicadors**")
    if t["enrichment"]:
        st.dataframe(pd.DataFrame(t["enrichment"])[["indicator", "result"]].rename(
            columns={"indicator": "Indicador", "result": "Resultat"}), hide_index=True, use_container_width=True)
    else:
        st.caption("No hi havia IP ni dominis per consultar.")
with c2:
    st.markdown(f"**Què recomana fer** {ui.example_tag(r, 'recommended_actions')}", unsafe_allow_html=True)
    acts = [{"Acció": ui.ACTION_LABEL.get(x["action"], x["action"]), "Sobre": x["target"],
             "Necessita aprovació?": "Sí, de N2" if x["requires_approval"] else "No"}
            for x in t["recommended_actions"]]
    if acts:
        st.dataframe(pd.DataFrame(acts), hide_index=True, use_container_width=True)
    if any(x["requires_approval"] for x in t["recommended_actions"]):
        if st.button("Anar a aprovar aquestes accions", key="ticket_to_contencion", icon=":material/shield:"):
            st.switch_page("views/accions_resposta.py")
    st.markdown("**Registres que ho avalen**")
    if t["evidence"]:
        st.dataframe(pd.DataFrame(t["evidence"]).rename(columns={"source": "Font", "event_id": "Registre",
                                                                 "finding": "Què mostra"}),
                     hide_index=True, use_container_width=True)
    else:
        st.caption("No s'han trobat registres relacionats.")

if t["open_questions"]:
    with st.container(border=True):
        st.markdown("**El que queda per comprovar**")
        for oq in t["open_questions"]:
            st.markdown(f"- {ui.md(oq)}")

# ---------------------------------------------------------------------------- JSON
st.divider()
err = validate(t)
v1, v2 = st.columns([3, 1], vertical_alignment="center")
if err == "sin-esquema":  # si cumple el esquema no se muestra nada; solo se avisa si algo falla
    v1.caption("No s'ha pogut comprovar el format: no es troba l'esquema de Deloitte.")
elif err is not None:
    v1.error(f"L'informe no compleix l'esquema: {err}")
v2.download_button("Descarregar l'informe (JSON)", json.dumps(t, ensure_ascii=False, indent=2),
                   file_name=f"{t['ticket_id']}.json", mime="application/json", use_container_width=True,
                   key="ticket_download", icon=":material/download:")
with st.expander("Veure l'informe tal com el rep el sistema (JSON)"):
    st.json(t)
