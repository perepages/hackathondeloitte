"""Propuesta de N1 sobre una alerta ya enriquecida: veredicto, gravedad final, cerrar/escalar y acciones.

Tres capas, en este orden:
  1. Propuesta del LLM (assistant.decide_json), con los datos marcados como <datos_no_fiables>.
  2. Red de seguridad: si no hay LLM, falla o devuelve algo inválido, el motor de reglas (rules.py: runbooks de
     Marc corregidos + reglas por caso de uso). Con el LLM, las reglas quedan como segunda opinión visible.
  3. Política SOC encima, SIEMPRE (la propuesta nunca la salta):
     - texto dirigido a nuestro clasificador (inyección) → true_positive y escalar;
     - gravedad = matriz ± 1 como máximo (VIP/privilegiado, ejecución, bloqueado…); actividad autorizada o
       falsa alarma → informational o low;
     - escalado obligatorio (true_positive high/critical, needs_more_info medium o más);
     - aprobación N2 para todo salvo purgar correo y bloquear IOC; nada sobre la red OT; uso dual con N2.

SOC_VERDICT_ENGINE: auto (LLM y, si falla, reglas; por defecto) | llm (igual, para dejarlo explícito) | rules.
"""
from __future__ import annotations

import os
import re

from policy import SEVERITY_CA, SEVERITY_ORDER, apply_severity_adjustment
from schemas import InjectionFlag, RecommendedAction, TriagePreview

VERDICTS = ("true_positive", "benign_true_positive", "false_positive", "needs_more_info")
ACTIONS = ("purge_email", "block_ioc", "revoke_sessions", "reset_password", "isolate_host", "disable_account",
           "disable_cloud_keys", "escalate", "close")
NO_APPROVAL = {"purge_email", "block_ioc", "escalate", "close"}
DUAL_USE = ("mega.nz", "mega.io", "anydesk.com", "teamviewer.com", "dropbox.com", "wetransfer.com")

# Solo texto dirigido a NUESTRO clasificador (no los prompts de clientes al asistente de compra,
# que son el objeto de la propia alerta UC-AI-001).
INJECTION = re.compile(
    r"(display\s*:\s*none|sistema automatizado|clasificaci[oó]n de seguridad|clasificar como|no escalar|"
    r"marcar como (false_positive|falso positivo))", re.I)


def engine() -> str:
    value = os.getenv("SOC_VERDICT_ENGINE", "auto").strip().lower()
    return value if value in ("auto", "llm", "rules") else "auto"


# ----------------------------------------------------------------------------- detección de inyección

def injection_flags(alert: dict) -> list[dict]:
    flags = []
    for key, value in (alert.get("evidence") or {}).items():
        if isinstance(value, str) and (m := INJECTION.search(value)):
            start = max(0, m.start() - 40)
            flags.append({"field": f"evidence.{key}", "excerpt": value[start:start + 160]})
    return flags


# ----------------------------------------------------------------------------- reglas (red de seguridad)

PLAIN = [  # lo que la IA a veces copia de sus instrucciones, dicho como lo ve la persona
    (r"\bbenign_true_positive\b", "activitat autoritzada"), (r"\btrue_positive\b", "atac real"),
    (r"\bfalse_positive\b", "falsa alarma"), (r"\bneeds_more_info\b", "falta informació"),
    (r"\s*\(?\s*cubre_esta_alerta\s*[=:]?\s*(false|fals)\s*\)?", " (no cobreix aquesta alerta)"),
    (r"\s*\(?\s*cubre_esta_alerta\s*[=:]?\s*(true|cert)\s*\)?", " (cobreix aquesta alerta)"),
    (r"\bseverity_adjustment\b", "ajust de gravetat"), (r"\bcambios_aprobados\b", "canvis aprovats"),
]


def plain_text(text: str) -> str:
    for pattern, repl in PLAIN:
        text = re.sub(pattern, repl, text, flags=re.I)
    return re.sub(r"\s{2,}", " ", text)


def _label(verdict: str) -> str:
    return {"true_positive": "atac real", "benign_true_positive": "activitat autoritzada",
            "false_positive": "falsa alarma", "needs_more_info": "falta informació"}.get(verdict, verdict)


def fact_adjustment(alert: dict, verdict: str, rules_view: dict | None, flags: list) -> int:
    """Ajuste de la política §2 calculado solo con hechos comprobados (nunca con la opinión de la IA, que puede
    cambiar de una ejecución a otra): −1 si un control lo bloqueó sin ejecución; +1 si un runbook confirma acceso o
    ejecución. El +1 por identidad VIP o privilegiada lo suma _severity (máximo ±1 en total)."""
    if verdict != "true_positive":
        return 0
    adjustment = 0
    if (rules_view and rules_view.get("verdict") == "true_positive"
            and str(rules_view.get("rule", "")).startswith("RB-") and (rules_view.get("severity_adjustment") or 0) > 0):
        adjustment = 1
    if blocked_by_control(alert):
        adjustment = -1
    if flags:  # quien intenta engañar al clasificador no rebaja la gravedad
        adjustment = max(0, adjustment)
    return adjustment


def blocked_by_control(alert: dict) -> bool:
    """Política §2, −1: un control lo bloqueó antes de producir efecto (WAF blocked, AV quarantined sin ejecución)."""
    ev = alert.get("evidence") or {}
    action = str(ev.get("action", "")).strip().lower()
    if action in ("blocked", "quarantined", "denied", "dropped") and str(ev.get("executed", "")).lower() != "true":
        return True
    # p. ej. credential stuffing frenado por el rate limit sin ningún acceso válido
    no_success = any(str(ev.get(k)) == "0" for k in ("success_count", "successes"))
    return no_success and str(ev.get("rate_limit", "")).lower() in ("activado", "activo", "on", "true", "enabled")


def rules_proposal(preview: dict) -> dict:
    """Propuesta del motor de reglas (rules.py: runbooks de Marc corregidos + reglas por caso de uso)."""
    import rules
    return rules.evaluate(preview)


def default_actions(alert: dict, verdict: str, escalate: bool) -> list[dict]:
    """Acciones típicas por caso de uso (las de las reglas de ejemplo)."""
    rule, ev, ent = alert.get("rule_id") or "", alert.get("evidence") or {}, alert.get("entities") or {}
    hosts = [h.get("hostname") for h in ent.get("hosts", []) if isinstance(h, dict) and h.get("hostname")]
    users = [u.get("upn") for u in ent.get("users", []) if isinstance(u, dict) and u.get("upn")]
    acts = []
    if verdict == "true_positive" and rule.startswith("UC-EML") and ev.get("sender"):
        acts.append({"action": "purge_email", "target": ev.get("message_id", "?"),
                     "justification": "Correu maliciós confirmat: retirar-lo de totes les bústies."})
        acts.append({"action": "block_ioc", "target": ev["sender"].split("@")[-1],
                     "justification": "Domini del remitent amb mala reputació."})
    if verdict == "true_positive" and rule.startswith("UC-IDP") and users:
        acts.append({"action": "revoke_sessions", "target": users[0], "justification": "Possible compte compromès."})
        acts.append({"action": "reset_password", "target": users[0], "justification": "Forçar el canvi de credencials."})
    if verdict == "true_positive" and escalate and hosts and rule.startswith(("UC-EDR", "UC-NET")):
        acts.append({"action": "isolate_host", "target": hosts[0],
                     "justification": "Execució o C2 confirmats a l'equip."})
    return acts


# ----------------------------------------------------------------------------- LLM

def llm_proposal(preview: dict) -> dict:
    """Propuesta del LLM validada. Lanza si no hay LLM, falla o la respuesta no sirve."""
    import assistant
    raw = assistant.decide_json({**preview, "verdict": None})  # que no lo condicione el needs_more_info inicial
    verdict = str(raw.get("verdict", "")).strip()
    if verdict not in VERDICTS:
        raise ValueError(f"veredicto no válido: {verdict!r}")
    try:
        confidence = max(0.0, min(1.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        confidence = None
    try:
        adjustment = max(-1, min(1, int(raw.get("severity_adjustment") or 0)))
    except (TypeError, ValueError):
        adjustment = 0
    decision = raw.get("decision") if raw.get("decision") in ("close", "escalate") else None
    actions = raw.get("recommended_actions") if isinstance(raw.get("recommended_actions"), list) else []
    text = lambda k: plain_text(str(raw.get(k) or "").strip())  # noqa: E731
    return {"verdict": verdict, "confidence": confidence, "severity_adjustment": adjustment, "decision": decision,
            "title": text("title"), "summary": text("summary"), "justification": text("justification"),
            "recommended_actions": actions, "injection_detected": raw.get("injection_detected") is True}


# ----------------------------------------------------------------------------- política

def _severity(verdict: str, matrix: str, matrix_rationale: str, vip: bool, adjustment: int) -> tuple[str, str]:
    if verdict in ("benign_true_positive", "false_positive"):
        severity = "informational" if matrix in ("informational", "low") else "low"
        label = "activitat autoritzada" if verdict == "benign_true_positive" else "falsa alarma"
        return severity, f"{matrix_rationale} Conclusió: {label} → {SEVERITY_CA[severity]} (política del SOC §2)."
    total = max(-1, min(1, (1 if vip else 0) + adjustment))
    severity = apply_severity_adjustment(matrix, total)
    reasons = []
    if vip:
        reasons.append("+1 identitat VIP o privilegiada")
    if adjustment > 0:
        reasons.append("+1 execució o accés confirmat")
    elif adjustment < 0:
        reasons.append("−1 bloquejat per un control sense activitat posterior")
    note = ""
    if reasons:
        note = f" Ajustos: {', '.join(reasons)}; total {total:+d} (màxim ±1) → {SEVERITY_CA[severity]}."
    return severity, matrix_rationale + note


def _ot_hosts(preview: dict) -> set[str]:
    out = set()
    for c in preview.get("contexts") or []:
        data = c.get("data") or {}
        if c.get("kind") == "asset" and "-OT" in str(data.get("zone", "")).upper():
            out.update(str(v) for v in (c.get("key"), data.get("hostname"), data.get("ip")) if v)
    return out


def _targets(action: str, target: str) -> list[str]:
    """Objetivos exactos de una acción. El LLM a veces escribe «a.example y b.example» o añade explicaciones:
    se separan y se quedan solo los trozos sin espacios (o un <message_id>)."""
    target = target.strip().strip("«»\"'`")
    if action in ("escalate", "close") or not re.search(r"\s", target):
        return [target] if target else []
    out = re.findall(r"<[^<>\s]+>", target)
    for part in re.split(r"\s*(?:,|;|\s+y\s+|\s+and\s+|\s+o\s+)\s*", re.sub(r"<[^<>\s]+>", " ", target)):
        tokens = [t.strip("().:«»\"'") for t in part.split()]
        out += [t for t in tokens if t and re.search(r"[.@:\-_]|\d", t) and not t.lower().startswith("message_id")]
    return list(dict.fromkeys(out))


def _actions(raw: list, decision: str, ot: set[str], notes: list[str]) -> list[dict]:
    out, seen = [], set()
    expanded = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", "")).strip().lower()
        targets = _targets(action, str(item.get("target") or ""))
        if action not in ("escalate", "close") and not targets and item.get("target"):
            notes.append(f"Es descarta «{action}»: l'objectiu «{str(item['target'])[:60]}» no és un valor exacte.")
        expanded += [{**item, "action": action, "target": t} for t in (targets or [""])]
    for item in expanded:
        action, target = item["action"], item["target"]
        if action not in ACTIONS or (action not in ("escalate", "close") and not target):
            continue
        if action == "close" and decision == "escalate" or action == "escalate" and decision == "close":
            continue
        if target in ot:
            notes.append(f"Es descarta «{action}» sobre {target}: és a la xarxa OT; només s'avisa Operacions.")
            continue
        approval = action not in NO_APPROVAL
        why = str(item.get("justification") or "").strip()
        if action == "block_ioc" and any(target == d or target.endswith("." + d) for d in DUAL_USE):
            approval = True
            why += " Servei legítim d'ús dual: bloquejar-lo per a tota l'empresa requereix N2."
        if (action, target) in seen:
            continue
        seen.add((action, target))
        out.append({"action": action, "target": target or "ticket", "requires_approval": approval,
                    "justification": why.strip()})
    if ot and decision == "escalate":
        out.append({"action": "escalate", "target": "Responsable d'Operacions", "requires_approval": False,
                    "justification": "Hi ha equips de la xarxa OT afectats: no s'hi actua, només s'escala."})
    if not any(a["action"] == decision for a in out) and not any(a["action"] not in ("escalate", "close") for a in out):
        out.append({"action": decision, "target": "ticket", "requires_approval": False,
                    "justification": "Escalar a N2 perquè ho revisi." if decision == "escalate"
                    else "Sense impacte: tancar amb justificació."})
    return out


def decide(preview: TriagePreview, *, matrix_severity: str, matrix_rationale: str,
           privileged_identity: bool) -> TriagePreview:
    """Rellena en `preview` la propuesta (veredicto, gravedad final, decisión, acciones…) y la devuelve."""
    data = preview.model_dump()
    alert = data["alert"]
    notes: list[str] = []

    proposal, source = None, "rules"
    if engine() != "rules":
        try:
            proposal, source = llm_proposal(data), "llm"
        except Exception as exc:  # sin LLM o respuesta inválida: reglas
            notes.append(f"La IA no ha donat una proposta vàlida ({str(exc)[:120]}); es fan servir les regles.")
    try:  # las reglas siempre opinan: respaldo si falla la IA y, si no, segunda opinión visible en pantalla
        rules_view = rules_proposal(data)
    except Exception as exc:
        rules_view = None
        notes.append(f"Les regles no han pogut avaluar l'alerta ({str(exc)[:120]}).")
    if proposal is None:
        if rules_view is None:
            rules_view = {"verdict": "needs_more_info", "confidence": 0.3, "severity_adjustment": 0, "decision": None,
                          "title": "", "summary": "", "justification": "Ni la IA ni les regles han pogut avaluar l'alerta.",
                          "recommended_actions": None, "injection_detected": False, "rule": ""}
        proposal = rules_view

    # Estabilidad: la IA solo propone el veredicto (y redacta). La gravedad y cerrar/escalar salen de reglas fijas
    # de la política aplicadas a hechos comprobados, así que con el mismo veredicto el resultado es siempre el mismo.
    verdict = proposal["verdict"]
    proposed_decision = proposal["decision"]
    justification = proposal["justification"]
    confidence = proposal["confidence"]
    flags = injection_flags(alert)
    if flags:
        if verdict != "true_positive":
            notes.append("Text ocult adreçat al sistema de classificació: es força «atac real» i escalar.")
            confidence = 0.9  # la conclusión la fija el texto oculto, no la propuesta
        verdict = "true_positive"
        justification = ("L'alerta conté text adreçat al sistema automàtic de classificació "
                         "(intent de manipulació). " + justification)
    elif proposal.get("injection_detected"):
        notes.append("La IA creu que les dades intenten manipular-la; cal revisar el text de l'alerta.")

    # Opción 2: la IA y las reglas no coinciden en si es un ataque -> conclusión dudosa, la revisa una persona
    attack = lambda v: {"true_positive": True, "benign_true_positive": False, "false_positive": False}.get(v)  # noqa
    doubtful = (source == "llm" and not flags and rules_view is not None
                and attack(verdict) is not None and attack(rules_view.get("verdict")) is not None
                and attack(verdict) != attack(rules_view["verdict"]))
    if doubtful:
        confidence = min(confidence if confidence is not None else 0.5, 0.5)

    severity, rationale = _severity(verdict, matrix_severity, matrix_rationale, privileged_identity,
                                    fact_adjustment(alert, verdict, rules_view, flags))

    reasons = []
    if flags:
        reasons.append("intent de manipulació del classificador")
    if doubtful:
        reasons.append(f"la IA i les regles dels runbooks no coincideixen (IA: {_label(verdict)}; regles: "
                       f"{_label(rules_view['verdict'])}): conclusió dubtosa")
    if verdict == "true_positive" and SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index("medium"):
        reasons.append(f"atac real de gravetat {SEVERITY_CA[severity]}")
    if verdict == "needs_more_info" and SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index("medium"):
        reasons.append("falten dades en una alerta de gravetat mitjana o superior")
    if (rules_view and rules_view.get("decision") == "escalate" and rules_view.get("verdict") == verdict
            and str(rules_view.get("rule", "")).startswith("RB-")):
        reasons.append(f"criteri d'escalat obligatori del runbook ({rules_view['rule']})")
    decision = "escalate" if reasons else "close"
    if source == "llm" and proposed_decision and proposed_decision != decision:
        notes.append(("S'escala" if decision == "escalate" else "Es tanca")
                     + f" tot i que la IA proposava {'escalar' if proposed_decision == 'escalate' else 'tancar'}: "
                     + ("; ".join(reasons) if reasons else
                        f"gravetat {SEVERITY_CA[severity]} i cap criteri d'escalat obligatori")
                     + " (política del SOC §3 i §5).")
    elif doubtful:
        notes.append(f"S'escala: {reasons[0]}.")

    raw_actions = proposal["recommended_actions"]
    if raw_actions is None:  # reglas: acciones típicas del caso de uso
        raw_actions = default_actions(alert, verdict, decision == "escalate")
    actions = _actions(raw_actions, decision, _ot_hosts(data), notes)

    open_questions = list(preview.open_questions)
    if verdict == "needs_more_info":
        open_questions.append("Les evidències no basten per a un veredicte: l'ha de completar una persona.")

    return preview.model_copy(update={
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity,
        "severity_rationale": rationale,
        "justification": justification,
        "decision": decision,
        "recommended_actions": [RecommendedAction(**a) for a in actions],
        "injection_flags": [InjectionFlag(**f) for f in flags],
        "title": proposal["title"] or f"{alert.get('rule_name')}",
        "summary": proposal["summary"] or justification,
        "decision_source": source,
        "decision_notes": notes,
        "rule_applied": (rules_view or {}).get("rule", "") if source == "rules" else "",
        "second_opinion": ({"verdict": rules_view["verdict"], "rule": rules_view.get("rule", ""),
                            "justification": rules_view["justification"]}
                           if source == "llm" and rules_view else None),
        "open_questions": list(dict.fromkeys(open_questions)),
    })
