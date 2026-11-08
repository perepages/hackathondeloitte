"""Ingesta de un JSONL nuevo en directo: líneas rotas, alertas que la API no reconoce y triaje en paralelo (sin red)."""
import json
import threading
import time

import pytest

from core import data
import soc_api


def test_parse_salta_lineas_rotas_y_sin_alert_id():
    text = "﻿" + "\n".join([
        json.dumps({"alert_id": "ALR-1", "status": "new"}),
        "{trencat",
        "",
        json.dumps({"rule_id": "UC-WEB-001"}),
        json.dumps(["no", "és", "un", "objecte"]),
        json.dumps({"alert_id": "ALR-2"}),
        json.dumps({"alert_id": "ALR-1"}),  # duplicada: s'ignora sense avisar
    ])
    ids, skipped = data.parse_alert_file(text.encode("utf-8"))
    assert ids == ["ALR-1", "ALR-2"]
    assert [(x["line"], x["reason"]) for x in skipped] == [
        (2, "no és un JSON vàlid"), (4, "no té alert_id"), (5, "no té alert_id")]


@pytest.fixture
def live(monkeypatch):
    monkeypatch.setattr(data, "MODE", "live")
    monkeypatch.setattr(data, "_store_live", lambda view: None)  # sin sesión de Streamlit
    # la API: cada alerta, de una regla distinta (que no s'agrupin entre elles); ALR-NOVA no hi és
    def fetch(alert_id):
        if alert_id == "ALR-NOVA":
            raise data.SkippedAlert("l'API del SOC no reconeix aquesta alerta")
        return {"alert_id": alert_id, "rule_id": f"UC-{alert_id}", "created_at": "2026-10-10T10:00:00Z"}
    monkeypatch.setattr(data, "_fetch_alert", fetch)


def _fake_view(alert_id):
    return {"alert_id": alert_id, "queries": [{"path": "/assets/X", "status": "ok"}], "decision": "close"}


def test_alerta_que_la_api_no_reconeix_es_salta_i_la_resta_continua(live, monkeypatch):
    def fake(alert_id, alert=None):
        if alert_id == "ALR-PETA":
            raise RuntimeError("boom")
        return _fake_view(alert_id)
    monkeypatch.setattr(data, "_triage_one", fake)
    events = []
    out = data.run_triage(["ALR-1", "ALR-NOVA", "ALR-PETA", "ALR-2"], events.append, workers=2)
    assert sorted(v["alert_id"] for v in out) == ["ALR-1", "ALR-2"]
    errors = {e["alert_id"]: e["message"] for e in events if e["type"] == "error"}
    assert errors["ALR-NOVA"] == "l'API del SOC no reconeix aquesta alerta" and "boom" in errors["ALR-PETA"]
    assert events[-1]["type"] == "done"


def test_404_de_la_api_es_converteix_en_alerta_saltada(monkeypatch):
    import triage
    def not_found(alert_id, **kw):
        raise soc_api.SocAPIError("no", status_code=404)
    monkeypatch.setattr(triage, "analyze_alert", not_found)
    monkeypatch.setattr(soc_api, "get_alert", not_found)
    with pytest.raises(data.SkippedAlert, match="no reconeix"):
        data._triage_one("ALR-X")
    with pytest.raises(data.SkippedAlert, match="no reconeix"):
        data._fetch_alert("ALR-X")


def test_tria_diverses_alhora_i_els_events_surten_del_fil_principal(live, monkeypatch):
    active, peak, lock = [0], [0], threading.Lock()

    def slow(alert_id, alert=None):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.2)
        with lock:
            active[0] -= 1
        return _fake_view(alert_id)
    monkeypatch.setattr(data, "_triage_one", slow)
    main = threading.current_thread()
    threads = set()
    t0 = time.time()
    out = data.run_triage([f"ALR-{i}" for i in range(8)], lambda e: threads.add(threading.current_thread()),
                          workers=4)
    assert len(out) == 8 and peak[0] == 4
    assert time.time() - t0 < 8 * 0.2  # en paral·lel, no una darrere l'altra
    assert threads == {main}  # Streamlit només pinta des del fil principal


def test_mode_mostra_avisa_si_l_alerta_no_hi_es(monkeypatch):
    monkeypatch.setattr(data, "MODE", "fixture")
    events = []
    data.run_triage(["ALR-QUE-NO-EXISTEIX"], events.append, pause=0)
    err = [e for e in events if e["type"] == "error"]
    assert err and "mode en directe" in err[0]["message"]


def test_taula_d_entitats_amb_les_tres_formes_del_dataset():
    """Llistes, un objecte (cloud) i un text sol (ai_session): cap valor lletra a lletra ni noms de camps."""
    from core import ui
    alert = {"entities": {"cloud": {"account": "tarvia-prod", "bucket": "tarvia-backups-prod"},
                          "ai_session": "ai-c07inj0001", "ips": ["198.19.95.151"],
                          "customers": [{"customer_id": "C1", "role": "víctima"}]}}
    rows = dict(zip(ui.entities_table(alert)["Què"], ui.entities_table(alert)["Quin"]))
    assert rows["Compte del núvol"] == "tarvia-prod" and rows["Bucket"] == "tarvia-backups-prod"
    assert rows["Sessió de l'assistent"] == "ai-c07inj0001"
    assert rows["Client"] == "C1 (víctima)"
    assert ui.main_entity({"alert": alert}) == "Bucket: tarvia-backups-prod"


def test_alerta_que_la_api_no_conoce_se_tria_con_los_datos_del_fichero(monkeypatch):
    """El día de la defensa el fichero puede traer alertas que no estén cargadas en la API: no se saltan."""
    from core import data
    content = ('{"alert_id": "ALR-NOVA-1", "rule_id": "UC-EDR-001", "rule_name": "Nova", "severity": "high", '
               '"created_at": "2026-11-08T10:00:00Z"}\n{"alert_id": "ALR-SENSE-REGLA"}\n')
    provided = data.alerts_in_file(content)
    assert list(provided) == ["ALR-NOVA-1"]  # sin regla no hay con qué triarla
    monkeypatch.setattr(data, "MODE", "live")

    def no_api(alert_id):
        raise data.SkippedAlert("l'API del SOC no reconeix aquesta alerta")
    seen = {}

    def fake_triage(alert_id, alert=None):
        seen[alert_id] = alert
        return {"alert_id": alert_id, "queries": [], "decision": "escalate"}
    monkeypatch.setattr(data, "_fetch_alert", no_api)
    monkeypatch.setattr(data, "_triage_one", fake_triage)
    monkeypatch.setattr(data, "_store_live", lambda view: None)
    events = []
    res = data.run_triage(["ALR-NOVA-1", "ALR-SENSE-REGLA"], events.append, provided=provided)
    assert [r["alert_id"] for r in res] == ["ALR-NOVA-1"] and seen["ALR-NOVA-1"]["_from_file"]
    assert [e["alert_id"] for e in events if e["type"] == "error"] == ["ALR-SENSE-REGLA"]
