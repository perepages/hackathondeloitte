"""Correlació / deduplicació temporal de nivell 1 (correlation.py), sense xarxa."""
import correlation


def _a(alert_id, t, rule="UC-CLD-003", severity="medium", events=(), **entities):
    return {"alert_id": alert_id, "created_at": f"2026-10-10T{t}Z", "rule_id": rule, "severity": severity,
            "entities": entities, "evidence": {"n": alert_id}, "related_events": list(events)}


BUCKET = {"cloud": {"bucket": "tarvia-media-public", "identity": "svc"}}


def test_agrupa_el_mateix_esdeveniment_dins_la_finestra():
    out = correlation.correlate([
        _a("A2", "09:07:34", events=["CT-2", "CT-3"], **BUCKET),
        _a("A1", "09:07:03", events=["CT-1", "CT-2"], **BUCKET),  # arriba desordenada: mana la primera en el temps
        _a("A3", "09:09:25", severity="high", events=["CT-3", "CT-4"], **BUCKET),
    ], window_min=5)
    assert len(out) == 1
    g = out[0]
    assert g["alert_id"] == "A1" and g["created_at"] == "2026-10-10T09:07:03Z"  # timestamp de la primera
    assert g["group"]["count"] == 3 and g["group"]["alert_ids"] == ["A1", "A2", "A3"]
    assert g["related_events"] == ["CT-1", "CT-2", "CT-3", "CT-4"]  # merge sense duplicats
    assert g["group"]["last_seen"] == "2026-10-10T09:09:25Z"
    assert g["severity"] == "high"  # la gravetat de regla més alta del grup
    assert "bucket:tarvia-media-public" in g["group"]["shared_keys"]


def test_fora_de_la_finestra_no_s_agrupa_i_la_finestra_es_configurable(monkeypatch):
    alerts = [_a("A1", "09:00:00", **BUCKET), _a("A2", "09:06:00", **BUCKET)]
    assert len(correlation.correlate(alerts, window_min=5)) == 2
    assert len(correlation.correlate(alerts, window_min=10)) == 1
    monkeypatch.setenv("SOC_DEDUP_WINDOW_MIN", "10")
    assert len(correlation.correlate(alerts)) == 1
    monkeypatch.setenv("SOC_DEDUP_WINDOW_MIN", "0")  # 0 la desactiva
    assert len(correlation.correlate(alerts)) == 2


def test_la_finestra_compta_des_de_la_primera_alerta_del_grup():
    alerts = [_a(f"A{i}", t, **BUCKET) for i, t in enumerate(["09:00:00", "09:04:00", "09:08:00"])]
    out = correlation.correlate(alerts, window_min=5)
    assert [g.get("group", {}).get("count", 1) for g in out] == [2, 1]


def test_cal_compartir_les_dades_clau():
    # mateixa regla i temps, però usuaris diferents que surten per la mateixa IP de l'oficina: no és el mateix
    a = _a("A1", "09:00:00", rule="UC-IDP-001", users=[{"upn": "anna@t.example"}], ips=["198.18.200.10"])
    b = _a("A2", "09:01:00", rule="UC-IDP-001", users=[{"upn": "pere@t.example"}], ips=["198.18.200.10"])
    assert len(correlation.correlate([a, b], window_min=5)) == 2
    # mateix usuari i mateixa IP: sí
    c = _a("A3", "09:02:00", rule="UC-IDP-001", users=[{"upn": "anna@t.example"}], ips=["198.18.200.10", "1.2.3.4"])
    out = correlation.correlate([a, c], window_min=5)
    assert len(out) == 1 and out[0]["entities"]["ips"] == ["198.18.200.10", "1.2.3.4"]
    # mateixes dades però regla diferent: no
    d = _a("A4", "09:01:00", rule="UC-IDP-003", users=[{"upn": "anna@t.example"}], ips=["198.18.200.10"])
    assert len(correlation.correlate([a, d], window_min=5)) == 2
    # sense cap dada clau comparable: no s'agrupa
    e1, e2 = _a("A5", "09:00:00", rule="UC-X"), _a("A6", "09:00:30", rule="UC-X")
    assert len(correlation.correlate([e1, e2], window_min=5)) == 2


def test_una_alerta_sola_no_canvia():
    a = _a("A1", "09:00:00", **BUCKET)
    out = correlation.correlate([a], window_min=5)
    assert out == [a] and "group" not in out[0]


def test_en_directe_s_agrupa_abans_de_la_ia(monkeypatch):
    """run_triage: llegeix, agrupa i tria UNA alerta per grup (amb la IA), amb l'event «grouped»."""
    from core import data
    alerts = {a["alert_id"]: a for a in [_a("A1", "09:00:00", **BUCKET), _a("A2", "09:01:00", **BUCKET),
                                          _a("B1", "09:02:00", rule="UC-OTRA", hosts=[{"hostname": "WS-1"}])]}
    triaged = []
    monkeypatch.setattr(data, "MODE", "live")
    monkeypatch.setattr(data, "_store_live", lambda view: None)
    monkeypatch.setattr(data, "_fetch_alert", lambda i: alerts[i])

    def fake(alert_id, alert=None):
        triaged.append((alert_id, (alert.get("group") or {}).get("count", 1)))
        return {"alert_id": alert_id, "queries": [], "decision": "close"}
    monkeypatch.setattr(data, "_triage_one", fake)
    events = []
    out = data.run_triage(["A1", "A2", "B1"], events.append, workers=2)
    assert sorted(triaged) == [("A1", 2), ("B1", 1)] and len(out) == 2
    assert [e for e in events if e["type"] == "grouped"] == [{"type": "grouped", "alert_id": "A1",
                                                              "members": ["A1", "A2"]}]
