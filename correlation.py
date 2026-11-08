"""Correlación / deduplicación temporal de nivel 1, ANTES del triaje y de la IA.

Varias alertas que son el mismo evento repetido (p. ej. cinco cambios de política del mismo bucket en tres minutos,
o el mismo escáner atacando el WAF dos veces) se agrupan en UNA alerta: el sistema y la IA la analizan una sola vez
y la persona ve un único caso con el número de eventos.

Dos alertas son el mismo evento si, a la vez:
  1. tienen la misma regla (rule_id);
  2. la segunda llega dentro de la ventana contada desde la PRIMERA alerta del grupo (SOC_DEDUP_WINDOW_MIN,
     5 minutos por defecto; 0 desactiva la agrupación);
  3. comparten los datos clave:
       - el mismo sujeto (equipo, usuario, cliente o bucket) si las dos tienen sujeto, y
       - el mismo indicador (IP, dominio, remitente o hash) si las dos tienen indicador,
     y al menos una de esas dos comprobaciones se ha podido hacer.
     (Con solo «compartir algo» se mezclaban, p. ej., viajes imposibles de personas distintas que salen por la misma
     IP de la oficina.)

La alerta agrupada conserva el alert_id y el created_at de la primera, une sin duplicados los related_events y las
entidades, toma la gravedad de regla más alta del grupo y añade:
    group = {count, alert_ids, first_seen, last_seen, window_min, shared_keys}
"""
from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timezone

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


def window_minutes() -> float:
    try:
        return max(0.0, float(os.getenv("SOC_DEDUP_WINDOW_MIN", "5")))
    except ValueError:
        return 5.0


def _ts(alert: dict) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(alert.get("created_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def key_data(alert: dict) -> tuple[set[str], set[str]]:
    """(sujetos, indicadores) de una alerta, normalizados para comparar."""
    ent, ev = alert.get("entities") or {}, alert.get("evidence") or {}
    subjects, indicators = set(), set()
    for h in ent.get("hosts") or []:
        name = (h.get("hostname") or h.get("ip")) if isinstance(h, dict) else h
        if name:
            subjects.add(f"equip:{str(name).lower()}")
    for u in ent.get("users") or []:
        upn = u.get("upn") if isinstance(u, dict) else u
        if upn and "@" in str(upn):  # «(161 cuentas)» no identifica a nadie
            subjects.add(f"usuari:{str(upn).lower()}")
    for c in ent.get("customers") or []:
        cid = c.get("customer_id") if isinstance(c, dict) else c
        if cid:
            subjects.add(f"client:{cid}")
    cloud = ent.get("cloud")
    if isinstance(cloud, dict) and cloud.get("bucket"):
        subjects.add(f"bucket:{cloud['bucket']}")
    for ip in ent.get("ips") or []:
        indicators.add(f"ip:{ip}")
    for d in ent.get("domains") or []:
        indicators.add(f"domini:{str(d).lower()}")
    for f in ent.get("files") or []:
        sha = f.get("sha256") if isinstance(f, dict) else None
        if sha:
            indicators.add(f"hash:{sha.lower()}")
    if ev.get("sender"):
        indicators.add(f"remitent:{str(ev['sender']).lower()}")
    return subjects, indicators


def _same_event(group: dict, alert: dict, subjects: set, indicators: set, window: float) -> bool:
    if group["rule_id"] != alert.get("rule_id"):
        return False
    t = _ts(alert)
    if t is None or group["first"] is None or not 0 <= (t - group["first"]).total_seconds() <= window * 60:
        return False
    checked = False
    for mine, other in ((group["subjects"], subjects), (group["indicators"], indicators)):
        if mine and other:
            if not mine & other:
                return False
            checked = True
    return checked


def _union(values: list) -> list:
    out, seen = [], set()
    for v in values:
        key = json.dumps(v, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def merge(alerts: list[dict], window: float, shared: set[str]) -> dict:
    """Una alerta con los datos de todas (la primera manda; ver el docstring del módulo)."""
    alerts = sorted(alerts, key=lambda a: _ts(a) or datetime.max.replace(tzinfo=timezone.utc))
    merged = copy.deepcopy(alerts[0])
    if len(alerts) == 1:
        return merged
    merged["related_events"] = _union([e for a in alerts for e in (a.get("related_events") or [])])
    entities: dict = {}
    for a in alerts:
        for k, v in (a.get("entities") or {}).items():
            if isinstance(v, list):
                entities[k] = _union((entities.get(k) or []) + v)
            elif isinstance(v, dict):
                entities[k] = {**v, **(entities.get(k) or {})}  # la primera manda
            elif k not in entities:
                entities[k] = v
    merged["entities"] = entities
    sev = [str(a.get("severity", "")).lower() for a in alerts if str(a.get("severity", "")).lower() in SEVERITY_ORDER]
    if sev:
        merged["severity"] = max(sev, key=SEVERITY_ORDER.index)
    merged["group"] = {
        "count": len(alerts),
        "alert_ids": [a["alert_id"] for a in alerts],
        "first_seen": alerts[0].get("created_at"),
        "last_seen": alerts[-1].get("created_at"),
        "window_min": window,
        "shared_keys": sorted(shared),
    }
    return merged


def correlate(alerts: list[dict], window_min: float | None = None) -> list[dict]:
    """Agrupa las alertas que son el mismo evento. Devuelve una alerta por grupo, en orden de llegada.
    Las alertas sin fecha válida no se agrupan con nada."""
    window = window_minutes() if window_min is None else max(0.0, float(window_min))
    ordered = sorted(alerts, key=lambda a: _ts(a) or datetime.max.replace(tzinfo=timezone.utc))
    if window <= 0:
        return [copy.deepcopy(a) for a in ordered]
    groups: list[dict] = []
    for alert in ordered:
        subjects, indicators = key_data(alert)
        target = next((g for g in reversed(groups) if _same_event(g, alert, subjects, indicators, window)), None)
        if target:
            target["alerts"].append(alert)
            target["shared"] &= subjects | indicators
            target["subjects"] |= subjects
            target["indicators"] |= indicators
        else:
            groups.append({"rule_id": alert.get("rule_id"), "first": _ts(alert), "alerts": [alert],
                           "subjects": set(subjects), "indicators": set(indicators),
                           "shared": subjects | indicators})
    return [merge(g["alerts"], window, g["shared"]) for g in groups]
