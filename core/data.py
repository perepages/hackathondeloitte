"""Única puerta del front a los datos (dueño: persona B).

Las páginas solo importan de aquí. Este módulo traduce la salida del back
(`triage.analyze_alert(...).model_dump()`, un TriagePreview) al CONTRATO DEL FRONT:
un diccionario plano y estable que las páginas pintan sin saber de dónde viene.

Modos (variable de entorno SOC_MODE):
  fixture (por defecto)  lee data/fixture.json; no necesita la API ni el back.
  live                   llama al back real (triage.analyze_alert) contra la API :8000.

Campos de ejemplo: el back (verdict.decide) ya da veredicto, decisión, acciones, inyección, título y
resumen; `decision_source` dice si la propuesta salió del LLM o de las reglas de respaldo. El fixture
trae además `_ejemplo` (reglas de prueba), que se usa SOLO si el back no da el campo;
esos campos quedan en `view["example_fields"]` y la interfaz los marca como «dato de ejemplo».
Con SOC_EXAMPLES=0 se desactivan y se ve el back tal cual.

CONTRATO DEL FRONT (lo que devuelve to_view):
  alert_id, alert (dict original), created_at, rule_id, rule_name, source_product, rule_severity
  verdict            true_positive | benign_true_positive | false_positive | needs_more_info
  confidence         0-1 o None
  severity           informational | low | medium | high | critical   (del back)
  severity_rationale texto (del back)
  asset_criticality  Baja | Media | Alta | Crítica | None
  justification, title, summary   texto
  decision           close | escalate
  recommended_actions  [{action, target, requires_approval, justification}]
  injection_flags      [{field, excerpt}]
  open_questions       [texto]   (del back)
  incident_id          texto o None   (incidents.py: alertas distintas de la misma intrusión, nivel 2)
  incident             {incident_id, title, count, decision, chain, severity} o None
  escalated_by_incident  True si se escala solo por formar parte de una cadena (política §5)
  queries   [{method, path, params, status (ok|not_found|error), result_count, note, summary}]
  contexts  [{kind, key, data}]   related_logs [dict]   (del back)
  decision_source  llm | rules | None      decision_notes  [correcciones de la política a la propuesta]
  rule_applied     regla que decidió (si decision_source == rules), p. ej. «RB-01 simulacro»
  second_opinion   {verdict, rule, justification} de las reglas cuando decidió la IA, o None
  example_fields  [nombres de campos que vienen de `_ejemplo`]
  review          {decision, analyst, note, at} o None   (decisión de la persona, de core/store)
"""
from __future__ import annotations

import json
import os
import time
from typing import Callable

import streamlit as st
from dotenv import load_dotenv

from core import store
from policy import criticality_ca

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# El .env, ANTES de leer SOC_MODE, SOC_EXAMPLES y SOC_WORKERS (antes solo lo cargaban assistant.py y soc_api.py, que
# se importan después, y estas tres se quedaban con el valor por defecto). No pisa lo que ya venga del entorno.
load_dotenv(os.path.join(ROOT, ".env"))
FIXTURE = os.path.join(ROOT, "data", "fixture.json")
MODE =os.getenv("SOC_MODE", "fixture").lower()
USE_EXAMPLES = os.getenv("SOC_EXAMPLES", "1") != "0"

# asset_criticality no está: la calcula to_view con el inventario (las reglas ponían «Media» si no había activo)
EXAMPLE_FIELDS = ("verdict", "confidence", "justification", "decision", "title",
                  "summary", "recommended_actions", "injection_flags")
_EMPTY = {"verdict": "needs_more_info", "confidence": None, "justification": "", "decision": "escalate",
          "asset_criticality": None, "title": "", "summary": "", "recommended_actions": [],
          "injection_flags": []}
CRIT_RANK = {"baja": 0, "media": 1, "alta": 2, "crítica": 3, "critica": 3}


# ----------------------------------------------------------------------------- traducción

def _ctx(contexts: list[dict], kind: str, key: str) -> dict | None:
    return next((c["data"] for c in contexts if c.get("kind") == kind and c.get("key") == key), None)


def _flag(v) -> bool:
    return str(v).lower() == "true"


def summarize_query(q: dict, contexts: list[dict]) -> str:
    """Una frase legible para cada consulta que hizo el back."""
    path, status = q.get("path", ""), q.get("status")
    if status == "not_found":
        return "no trobat (desconegut no vol dir net)"
    if status == "error":
        return f"error: {(q.get('note') or '')[:120]}"
    key = path.rsplit("/", 1)[-1]
    if path.startswith("/assets/") and (a := _ctx(contexts, "asset", key)):
        return f"{a.get('hostname')} · criticitat {criticality_ca(a.get('criticality'))} · zona {a.get('zone')} · {a.get('business_service')}"
    if path.startswith("/users/") and (u := _ctx(contexts, "user", key)):
        tags = [t for t, k in (("VIP", "vip"), ("privilegiat", "privileged")) if _flag(u.get(k))]
        return f"{u.get('display_name')} · {u.get('title')} ({u.get('department')})" + (" · " + ", ".join(tags) if tags else "")
    if path.startswith("/intel/") and (i := _ctx(contexts, "intel", key)) is not None:
        tip, geo = i.get("tip"), i.get("geo")
        parts = [f"TIP: {tip['reputation']} ({tip.get('tags')}, confiança {tip.get('confidence')})" if tip
                 else "TIP: sense dades"]
        if geo:
            fl = [n for n, k in (("Tor", "is_tor"), ("VPN", "is_vpn_provider"), ("hosting", "is_hosting")) if _flag(geo.get(k))]
            parts.append(f"{geo.get('as_org')} ({geo.get('country')})" + (" · " + ", ".join(fl) if fl else ""))
        return " · ".join(parts)
    if path.startswith("/sandbox/") and (s := _ctx(contexts, "sandbox", key)):
        return f"sandbox: {s.get('verdict', 'informe disponible')}"
    if path == "/changes":
        n = q.get("result_count") or 0
        return f"{n} canvi(s) aprovat(s)" if n else "cap canvi aprovat no hi coincideix"
    if path.startswith("/logs/"):
        return f"{q.get('result_count') or 0} esdeveniment(s) a {path.split('/')[2]} (±24 h)"
    return "ok"


def to_view(preview: dict) -> dict:
    """TriagePreview del back (+ `_ejemplo` opcional) -> contrato del front."""
    alert, contexts = preview["alert"], preview.get("contexts") or []
    ej = (preview.get("_ejemplo") or {}) if USE_EXAMPLES else {}
    view = {
        "alert_id": alert["alert_id"], "alert": alert, "created_at": alert.get("created_at") or "",
        "rule_id": alert.get("rule_id") or "", "rule_name": alert.get("rule_name") or "",
        "source_product": alert.get("source_product") or "", "rule_severity": (alert.get("severity") or "medium").lower(),
        "severity": preview.get("severity"), "severity_rationale": preview.get("severity_rationale", ""),
        "open_questions": preview.get("open_questions") or [], "contexts": contexts,
        "related_logs": preview.get("related_logs") or [],
        "queries": [{**q, "summary": summarize_query(q, contexts)} for q in preview.get("queries") or []],
        "example_fields": [],
        # correlación de nivel 1: {count, alert_ids, first_seen, last_seen, window_min, shared_keys} o None
        "group": alert.get("group"),
        # incidente de nivel 2: lo pone incidents.apply al cargar todos los resultados (necesita verlos juntos)
        "incident_id": None, "incident": None,
    }
    # criticidad: la del activo más crítico que devolvió el back
    crits = [str(c["data"].get("criticality")) for c in contexts if c.get("kind") == "asset" and c["data"].get("criticality")]
    view["asset_criticality"] = max(crits, key=lambda c: CRIT_RANK.get(c.lower(), -1)) if crits else None

    view["decision_source"] = preview.get("decision_source")  # llm | rules | None (back sin propuesta)
    view["decision_notes"] = preview.get("decision_notes") or []
    view["rule_applied"] = preview.get("rule_applied") or ""
    view["second_opinion"] = preview.get("second_opinion")
    decided = view["decision_source"] is not None
    for f in EXAMPLE_FIELDS:
        back_value = preview.get(f, view.get(f))
        # Si el back ya ha decidido, sus listas vacías y su needs_more_info son respuesta, no hueco.
        back_gives = (back_value not in (None, "", []) and not (f == "verdict" and back_value == "needs_more_info")
                      or decided and f in ("verdict", "injection_flags", "recommended_actions"))
        if back_gives:
            view[f] = back_value
        elif ej.get(f) not in (None, "", []):
            view[f] = ej[f]
            view["example_fields"].append(f)
        else:
            view[f] = back_value if back_value not in (None, "") else _EMPTY[f]
    return view


# ----------------------------------------------------------------------------- lectura

@st.cache_data(show_spinner=False)
def _load_fixture() -> list[dict]:
    with open(FIXTURE, encoding="utf-8") as f:
        return [to_view(p) for p in json.load(f)]


def _with_incidents() -> tuple[list[dict], list[dict]]:
    """Resultados con la decisión de la persona y los incidentes de nivel 2 (incidents.py) ya aplicados."""
    import incidents
    rows = _load_fixture() if MODE == "fixture" else st.session_state.get("data_live_results", [])
    reviews = store.list_reviews()
    out = [{**r, "review": reviews.get(r["alert_id"])} for r in rows]  # copias: apply no toca la caché
    incs = incidents.apply(out)
    return sorted(out, key=lambda r: r["created_at"]), incs


def load_results() -> list[dict]:
    """Todos los resultados, ordenados por fecha, con la decisión de la persona unida."""
    return _with_incidents()[0]


def load_incidents() -> list[dict]:
    """Incidentes (alertas distintas de la misma intrusión), de más a menos grave. Ver incidents.py."""
    return _with_incidents()[1]


def get_incident(incident_id: str) -> tuple[dict | None, list[dict]]:
    """(incidente, sus resultados en orden de llegada)."""
    rows, incs = _with_incidents()
    inc = next((i for i in incs if i["incident_id"] == incident_id), None)
    return inc, [r for r in rows if inc and r["incident_id"] == incident_id]


def get_result(alert_id: str) -> dict | None:
    return next((r for r in load_results() if r["alert_id"] == alert_id), None)


def _example_fields(alert: dict) -> dict | None:
    """Campos de ejemplo (veredicto, decisión, acciones…) con las mismas reglas de prueba que la muestra.
    Solo rellenan lo que el back todavía no da; salen marcados como «dato de ejemplo»."""
    try:
        import importlib.util
        path = os.path.join(ROOT, "scripts", "build_fixture.py")
        spec = importlib.util.spec_from_file_location("build_fixture", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.example_fields(alert)
    except Exception:  # sin reglas de ejemplo se ve el back tal cual
        return None


WORKERS = int(os.getenv("SOC_WORKERS", "4"))  # alertas triadas a la vez en directo (API + IA)


class SkippedAlert(Exception):
    """Alerta que no se puede triar (p. ej. la API del SOC no la reconoce). Se salta y se avisa; no para el lote."""


def _fetch_alert(alert_id: str) -> dict:
    """La alerta tal como la tiene la API del SOC (fuente de verdad). Si no la reconoce, se salta."""
    import soc_api
    try:
        return soc_api.get_alert(alert_id)
    except soc_api.SocAPIError as exc:
        if exc.status_code == 404:
            raise SkippedAlert("l'API del SOC no reconeix aquesta alerta") from exc
        raise SkippedAlert(f"error de l'API del SOC: {str(exc)[:120]}") from exc


def _triage_one(alert_id: str, alert: dict | None = None) -> dict:
    """Tría una alerta (o una alerta agrupada ya leída) con el back y devuelve la vista. Sin Streamlit: se puede
    llamar desde varios hilos."""
    import soc_api
    from triage import analyze_alert
    try:
        preview = analyze_alert(alert_id, alert=alert).model_dump()
    except soc_api.SocAPIError as exc:
        if exc.status_code == 404:
            raise SkippedAlert("l'API del SOC no reconeix aquesta alerta") from exc
        raise SkippedAlert(f"error de l'API del SOC: {str(exc)[:120]}") from exc
    if USE_EXAMPLES and (ej := _example_fields(preview["alert"])):
        preview["_ejemplo"] = ej
    view = to_view(preview)
    if (alert or {}).get("_from_file"):
        view["decision_notes"] = ["L'API del SOC no coneixia aquesta alerta: s'ha triat amb les dades del fitxer i el "
                                  "context que sí té l'API (equips, usuaris, intel·ligència, registres)."] \
                                 + view["decision_notes"]
    return view


def _store_live(view: dict) -> None:
    live = [r for r in st.session_state.get("data_live_results", []) if r["alert_id"] != view["alert_id"]]
    st.session_state["data_live_results"] = live + [view]


def analyze_live(alert_id: str) -> dict:
    """Llama al back real (necesita la API :8000)."""
    view = _triage_one(alert_id)
    _store_live(view)
    return view


def refresh() -> None:
    """Botón «Actualitzar alertes»: vuelve a leer la bandeja (resultados, revisiones e incidentes). No tría nada:
    en la API de Deloitte las ~11.000 alertas del dataset están todas en estado «new» y no entra ninguna nueva, así
    que «tría las nuevas de la cola» metía siempre las 5 primeras del dataset (viejas y del mismo tipo). Las alertas
    se tría desde «Triatge en directe» (fichero o lista de ids)."""
    _load_fixture.clear()


def parse_alert_file(content: bytes | str) -> tuple[list[str], list[dict]]:
    """Lee un JSONL de alertas (el que nos den el día de la defensa) sin romperse.

    Devuelve (ids válidos, sin duplicados y en orden) y la lista de líneas saltadas [{line, reason}]:
    JSON roto, una línea que no es un objeto o sin alert_id. Las líneas en blanco se ignoran sin avisar."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    ids, skipped = [], []
    for n, line in enumerate(content.lstrip("\ufeff").splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            skipped.append({"line": n, "reason": "no és un JSON vàlid"})
            continue
        alert_id = obj.get("alert_id") if isinstance(obj, dict) else None
        if not isinstance(alert_id, str) or not alert_id.strip():
            skipped.append({"line": n, "reason": "no té alert_id"})
            continue
        if alert_id.strip() not in ids:
            ids.append(alert_id.strip())
    return ids, skipped


def alerts_in_file(content: bytes | str) -> dict[str, dict]:
    """Las alertas completas del fichero, por id (las líneas rotas no). Sirven para triar una alerta que la API del
    SOC no conoce: el día de la defensa el fichero puede traer alertas que no estén cargadas en la API."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    out = {}
    for line in content.lstrip("﻿").splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("alert_id"), str) and obj.get("rule_id"):
            out.setdefault(obj["alert_id"].strip(), {**obj, "alert_id": obj["alert_id"].strip()})
    return out


def load_alert_ids_from_jsonl(content: bytes | str) -> list[str]:
    """IDs válidos de un JSONL de alertas (las líneas rotas se saltan; ver parse_alert_file)."""
    return parse_alert_file(content)[0]


# ----------------------------------------------------------------------------- directo

def run_triage(alert_ids: list[str], on_event: Callable[[dict], None], pause: float = 0.35,
               workers: int | None = None, provided: dict[str, dict] | None = None) -> list[dict]:
    """Tría una lista y avisa de cada paso con los eventos del contrato:
    alert_started -> api_call (uno por consulta) -> verdict | error ... -> done.

    live: tría `workers` alertas a la vez (por defecto 4). Si una falla (p. ej. la API no la reconoce), se emite
    `error` con el motivo y se sigue con las demás: nunca se para el lote. fixture: reproduce la muestra con pausas.
    Los eventos se emiten siempre desde el hilo principal (Streamlit solo pinta desde ahí)."""
    results: list[dict] = []
    if MODE == "fixture":
        by_id = {}
        for r in load_results():  # una alerta agrupada responde también por los ids de las que agrupa
            for i in [r["alert_id"], *((r.get("group") or {}).get("alert_ids") or [])]:
                by_id.setdefault(i, r)
        seen = set()
        for alert_id in alert_ids:
            view = by_id.get(alert_id)
            if view is not None:
                if view["alert_id"] in seen:  # otra alerta del mismo grupo: ya está
                    continue
                seen.add(view["alert_id"])
                if view.get("group"):
                    on_event({"type": "grouped", "alert_id": view["alert_id"],
                              "members": [i for i in view["group"]["alert_ids"] if i in alert_ids]})
                alert_id = view["alert_id"]
            on_event({"type": "alert_started", "alert_id": alert_id})
            if view is None:
                on_event({"type": "error", "alert_id": alert_id,
                          "message": "no és a la mostra (per triar alertes noves cal el mode en directe)"})
                continue
            for q in view["queries"]:
                on_event({"type": "api_call", "alert_id": alert_id, **q})
                time.sleep(pause)
            on_event({"type": "verdict", "alert_id": alert_id, "result": view})
            results.append(view)
        on_event({"type": "done"})
        return results

    import correlation
    from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
    n_workers = max(1, workers or WORKERS)

    # 1) Leer las alertas de la API (fuente de verdad); las que no reconoce se saltan
    fetched: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(_fetch_alert, a): a for a in dict.fromkeys(alert_ids)}
        for future in as_completed(futures):
            alert_id = futures[future]
            try:
                fetched[alert_id] = future.result()
            except Exception as exc:
                if alert_id in (provided or {}):  # la API no la té (o no respon): es tria amb les dades del fitxer
                    fetched[alert_id] = {**provided[alert_id], "_from_file": True}
                    continue
                msg = str(exc) if isinstance(exc, SkippedAlert) else f"error en llegir-la: {str(exc)[:120]}"
                on_event({"type": "error", "alert_id": alert_id, "message": msg})

    # 2) Correlación de nivel 1: el mismo evento repetido en la ventana -> una sola alerta (antes de la IA)
    grouped = correlation.correlate([fetched[a] for a in dict.fromkeys(alert_ids) if a in fetched])
    for alert in grouped:
        if alert.get("group"):
            on_event({"type": "grouped", "alert_id": alert["alert_id"], "members": alert["group"]["alert_ids"]})

    # 3) Triar una alerta por grupo, `n_workers` a la vez
    pending, running = list(grouped), {}
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        while pending or running:
            while pending and len(running) < n_workers:
                alert = pending.pop(0)
                alert_id = alert["alert_id"]
                on_event({"type": "alert_started", "alert_id": alert_id})
                running[pool.submit(_triage_one, alert_id, alert)] = alert_id
            finished, _ = wait(running, return_when=FIRST_COMPLETED)
            for future in finished:
                alert_id = running.pop(future)
                try:
                    view = future.result()
                except SkippedAlert as exc:
                    on_event({"type": "error", "alert_id": alert_id, "message": str(exc)})
                    continue
                except Exception as exc:  # cualquier otro fallo de esa alerta: se salta, el resto sigue
                    on_event({"type": "error", "alert_id": alert_id, "message": f"error en triar-la: {str(exc)[:120]}"})
                    continue
                _store_live(view)
                for q in view["queries"]:
                    on_event({"type": "api_call", "alert_id": alert_id, **q})
                on_event({"type": "verdict", "alert_id": alert_id, "result": view})
                results.append(view)
    on_event({"type": "done"})
    return results


# ----------------------------------------------------------------------------- contención (nivel 4)

NO_APPROVAL = {"block_ioc", "purge_email"}
# Nuestros nombres de acción (los de la política y el ticket) -> los que acepta la API de Deloitte
# (mock_soc_api.VALID). Sin esto, la API respondía «acción no soportada» al ejecutarlas.
API_ACTION = {"disable_account": "disable_user", "disable_cloud_keys": "disable_access_key"}


def api_action(action: str) -> str:
    return API_ACTION.get(action, action)


def approve(action: str, target: str, approver: str, reason: str) -> str:
    """Registra la aprobación humana y devuelve el token. Simulado en modo fixture."""
    if MODE == "fixture":
        return f"APR-SIMULADO-{abs(hash((action, target))) % 10**6:06d}"
    import httpx, soc_api
    r = httpx.post(f"{soc_api.BASE_URL}/approvals", json={"action": api_action(action), "target": target,
                                                          "approver": approver, "reason": reason}, timeout=15)
    r.raise_for_status()
    return r.json()["approval_token"]


def ticket_id(row: dict) -> str:
    """El ticket on queda registrada l'alerta: el de l'incident si en forma part (política §6), si no el seu."""
    return f"TKT-{row.get('incident_id') or row['alert_id']}"


def contain(action: str, target: str, justification: str, token: str = "", ticket: str = "") -> dict:
    """Ejecuta la contención en la API simulada (con el ticket, para la trazabilidad). Simulado en modo fixture."""
    if MODE == "fixture":
        return {"action": action, "target": target, "ticket_id": ticket, "result": "ok (simulado, modo fixture)"}
    import httpx, soc_api
    r = httpx.post(f"{soc_api.BASE_URL}/containment/{api_action(action)}", json={
        "target": target, "justification": justification, "approval_token": token, "ticket_id": ticket},
        timeout=15)
    r.raise_for_status()
    return r.json()


# ----------------------------------------------------------------------------- plan de acción (LLM)

def llm_status() -> tuple[bool, str]:
    """(¿hay LLM?, descripción). El LLM lo pone el back: assistant.py."""
    import assistant
    return assistant.available()


def action_plan(view: dict):
    """Plan de acción redactado por el LLM, a trozos (para st.write_stream). El LLM solo redacta: no decide."""
    import assistant
    return assistant.action_plan(view)


def plan_in_catalan(text: str) -> str:
    """El plan, traducido al catalán si la IA lo escribió en castellano (si no, igual)."""
    import assistant
    return assistant.to_catalan_text(text)


# ----------------------------------------------------------------------------- alertas para el directo

def suggest_ids(n: int = 10) -> list[str]:
    """Alertas de ejemplo para el directo: variadas (una por regla).

    fixture: 5 que se cierran y 5 que se escalan de la muestra.
    live:    de la cola real de la API de Deloitte (alertas que no están en la muestra de desarrollo)."""
    if MODE == "fixture":
        seen, pick = set(), []
        for want in ("close", "escalate"):
            k = 0
            for r in load_results():
                if r["decision"] == want and r["rule_id"] not in seen and k < n // 2:
                    seen.add(r["rule_id"]); pick.append(r["alert_id"]); k += 1
        return pick
    import soc_api
    items = soc_api.list_alerts(status="new", limit=600, offset=4000).get("items", [])
    seen, pick = set(), []
    for a in items:
        if a.get("rule_id") not in seen:
            seen.add(a.get("rule_id")); pick.append(a["alert_id"])
        if len(pick) == n:
            break
    return pick


@st.cache_data(show_spinner=False)
def alert_brief(alert_id: str) -> dict:
    """Nombre, origen y hora de una alerta aún sin triar (para pintar su tarjeta). Vacío si no se puede."""
    if MODE == "fixture":
        return {}
    try:
        import soc_api
        a = soc_api.get_alert(alert_id)
        return {"rule_name": a.get("rule_name", alert_id), "source_product": a.get("source_product", ""),
                "created_at": a.get("created_at", "")}
    except Exception:
        return {}
