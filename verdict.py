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

from policy import SEVERITY_ORDER, apply_severity_adjustment
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

def blocked_by_control(alert: dict) -> bool:
    """Política §2, −1: un control lo bloqueó antes de producir efecto (WAF blocked, AV quarantined sin ejecución)."""
    ev = alert.get("evidence") or {}
    action = str(ev.get("action", "")).strip().lower()
    return action in ("blocked", "quarantined", "denied", "dropped") and str(ev.get("executed", "")).lower() != "true"


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
                     "justification": "Correo malicioso confirmado: retirarlo de todos los buzones."})
        acts.append({"action": "block_ioc", "target": ev["sender"].split("@")[-1],
                     "justification": "Dominio del remitente con mala reputación."})
    if verdict == "true_positive" and rule.startswith("UC-IDP") and users:
        acts.append({"action": "revoke_sessions", "target": users[0], "justification": "Posible cuenta comprometida."})
        acts.append({"action": "reset_password", "target": users[0], "justification": "Forzar cambio de credenciales."})
    if verdict == "true_positive" and escalate and hosts and rule.startswith(("UC-EDR", "UC-NET")):
        acts.append({"action": "isolate_host", "target": hosts[0],
                     "justification": "Ejecución o C2 confirmados en el puesto."})
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
    text = lambda k: str(raw.get(k) or "").strip()  # noqa: E731
    return {"verdict": verdict, "confidence": confidence, "severity_adjustment": adjustment, "decision": decision,
            "title": text("title"), "summary": text("summary"), "justification": text("justification"),
            "recommended_actions": actions, "injection_detected": raw.get("injection_detected") is True}


# ----------------------------------------------------------------------------- política

def _severity(verdict: str, matrix: str, matrix_rationale: str, vip: bool, adjustment: int) -> tuple[str, str]:
    if verdict in ("benign_true_positive", "false_positive"):
        severity = "informational" if matrix in ("informational", "low") else "low"
        label = "actividad autorizada" if verdict == "benign_true_positive" else "falsa alarma"
        return severity, f"{matrix_rationale} Conclusión: {label} → {severity} (política SOC §2)."
    total = max(-1, min(1, (1 if vip else 0) + adjustment))
    severity = apply_severity_adjustment(matrix, total)
    reasons = []
    if vip:
        reasons.append("+1 identidad VIP o privilegiada")
    if adjustment > 0:
        reasons.append("+1 ejecución o acceso confirmado")
    elif adjustment < 0:
        reasons.append("−1 bloqueado por un control sin actividad posterior")
    note = ""
    if reasons:
        note = f" Ajustes: {', '.join(reasons)}; total {total:+d} (máximo ±1) → {severity}."
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
            notes.append(f"Se descarta «{action}»: el objetivo «{str(item['target'])[:60]}» no es un valor exacto.")
        expanded += [{**item, "action": action, "target": t} for t in (targets or [""])]
    for item in expanded:
        action, target = item["action"], item["target"]
        if action not in ACTIONS or (action not in ("escalate", "close") and not target):
            continue
        if action == "close" and decision == "escalate" or action == "escalate" and decision == "close":
            continue
        if target in ot:
            notes.append(f"Se descarta «{action}» sobre {target}: está en la red OT; solo se avisa a Operaciones.")
            continue
        approval = action not in NO_APPROVAL
        why = str(item.get("justification") or "").strip()
        if action == "block_ioc" and any(target == d or target.endswith("." + d) for d in DUAL_USE):
            approval = True
            why += " Servicio legítimo de uso dual: bloquearlo de forma global requiere N2."
        if (action, target) in seen:
            continue
        seen.add((action, target))
        out.append({"action": action, "target": target or "ticket", "requires_approval": approval,
                    "justification": why.strip()})
    if ot and decision == "escalate":
        out.append({"action": "escalate", "target": "Responsable de Operaciones", "requires_approval": False,
                    "justification": "Hay equipos de la red OT afectados: no se actúa sobre ellos, solo se escala."})
    if not any(a["action"] == decision for a in out) and not any(a["action"] not in ("escalate", "close") for a in out):
        out.append({"action": decision, "target": "ticket", "requires_approval": False,
                    "justification": "Escalar a N2 para revisión." if decision == "escalate"
                    else "Sin impacto: cerrar con justificación."})
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
            notes.append(f"La IA no dio una propuesta válida ({str(exc)[:120]}); se usan las reglas.")
    try:  # las reglas siempre opinan: respaldo si falla la IA y, si no, segunda opinión visible en pantalla
        rules_view = rules_proposal(data)
    except Exception as exc:
        rules_view = None
        notes.append(f"Las reglas no pudieron evaluar la alerta ({str(exc)[:120]}).")
    if proposal is None:
        if rules_view is None:
            rules_view = {"verdict": "needs_more_info", "confidence": 0.3, "severity_adjustment": 0, "decision": None,
                          "title": "", "summary": "", "justification": "Ni la IA ni las reglas pudieron evaluar la alerta.",
                          "recommended_actions": None, "injection_detected": False, "rule": ""}
        proposal = rules_view

    verdict = proposal["verdict"]
    decision = proposal["decision"]
    justification = proposal["justification"]
    flags = injection_flags(alert)
    if flags:
        if verdict != "true_positive" or decision != "escalate":
            notes.append("Texto oculto dirigido al sistema de clasificación: se fuerza «true_positive» y escalar.")
        verdict, decision = "true_positive", "escalate"
        justification = ("La alerta contiene texto dirigido al sistema automático de clasificación "
                         "(intento de manipulación). " + justification)
    elif proposal.get("injection_detected"):
        notes.append("La IA cree que los datos intentan manipularla; revisar el texto de la alerta.")

    adjustment = proposal.get("severity_adjustment") or 0
    if verdict == "true_positive" and blocked_by_control(alert) and adjustment >= 0:
        if adjustment > 0:
            notes.append("La propuesta subía la gravedad, pero la evidencia dice que un control lo bloqueó sin "
                         "ejecución: se aplica −1 (política SOC §2).")
        adjustment = -1
    if (rules_view and rules_view.get("verdict") == verdict == "true_positive"
            and str(rules_view.get("rule", "")).startswith("RB-")  # solo hechos comprobados por un runbook
            and (rules_view.get("severity_adjustment") or 0) > 0 and adjustment <= 0):
        # hecho objetivo que las reglas han comprobado (ejecución o acceso confirmado): +1 de la política §2
        adjustment = 1
    if flags:  # quien intenta engañar al clasificador no rebaja la gravedad
        adjustment = max(0, adjustment)
    severity, rationale = _severity(verdict, matrix_severity, matrix_rationale, privileged_identity, adjustment)

    forced = None
    if verdict == "true_positive" and severity in ("high", "critical"):
        forced = "true_positive de gravedad alta o crítica"
    elif verdict == "needs_more_info" and SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index("medium"):
        forced = "faltan datos en una alerta de gravedad media o superior"
    elif flags:
        forced = "intento de manipulación del clasificador"
    if forced:
        if decision == "close":
            notes.append(f"Se escala aunque la propuesta era cerrar: {forced} (política SOC §5).")
        decision = "escalate"
    elif (severity in ("informational", "low") and decision == "escalate" and source == "llm"
          and (rules_view or {}).get("decision") != "escalate"):
        # §3: gravedad baja o informativa no se escala; los casos obligatorios del §5 (fraude, credenciales,
        # ejecución) los marcan las reglas con decision=escalate y entonces se respeta
        notes.append(f"Se cierra aunque la IA proponía escalar: gravedad {severity} y ningún criterio de escalado "
                     "obligatorio (política SOC §3 y §5).")
        decision = "close"
    elif decision is None:
        decision = "close"

    raw_actions = proposal["recommended_actions"]
    if raw_actions is None:  # reglas: acciones típicas del caso de uso
        raw_actions = default_actions(alert, verdict, decision == "escalate")
    actions = _actions(raw_actions, decision, _ot_hosts(data), notes)

    open_questions = list(preview.open_questions)
    if verdict == "needs_more_info":
        open_questions.append("Las evidencias no bastan para un veredicto: una persona debe completarlo.")

    return preview.model_copy(update={
        "verdict": verdict,
        "confidence": proposal["confidence"],
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
