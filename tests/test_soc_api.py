import soc_api


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.status_code = 200
        self.text = ""

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_list_alerts_calls_the_documented_endpoint(monkeypatch):
    seen = {}

    def fake_get(url, *, params, timeout):
        seen.update(url=url, params=params, timeout=timeout)
        return FakeResponse({"total": 1, "items": [{"alert_id": "ALR-1"}]})

    monkeypatch.setattr(soc_api, "BASE_URL", "http://soc.test")
    monkeypatch.setattr(soc_api.httpx, "get", fake_get)

    result = soc_api.list_alerts(limit=3)

    assert seen["url"] == "http://soc.test/alerts"
    assert seen["params"] == {"status": "new", "limit": 3, "offset": 0}
    assert result["items"][0]["alert_id"] == "ALR-1"


def test_get_alert_uses_the_alert_id_in_the_path(monkeypatch):
    seen = {}

    def fake_get(url, *, params, timeout):
        seen["url"] = url
        return FakeResponse({"alert_id": "ALR-42"})

    monkeypatch.setattr(soc_api, "BASE_URL", "http://soc.test")
    monkeypatch.setattr(soc_api.httpx, "get", fake_get)

    result = soc_api.get_alert("ALR-42")

    assert seen["url"] == "http://soc.test/alerts/ALR-42"
    assert result["alert_id"] == "ALR-42"


def test_las_acciones_se_llaman_como_las_acepta_la_api_de_deloitte(monkeypatch):
    """Nuestros nombres (política/ticket) -> los de mock_soc_api.VALID. Antes la API respondía «acción no soportada»."""
    import httpx
    from core import data
    monkeypatch.setattr(data, "MODE", "live")
    sent = []

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"approval_token": "APR-1", "result": "ok"}

    monkeypatch.setattr(httpx, "post", lambda url, json, timeout: sent.append((url, json)) or R())
    data.approve("disable_account", "u@x", "N2", "prova")
    data.contain("disable_cloud_keys", "AKIA1", "prova", "APR-1")
    data.contain("isolate_host", "WS-1", "prova", "APR-1")
    assert sent[0][1]["action"] == "disable_user"
    assert sent[1][0].endswith("/containment/disable_access_key")
    assert sent[2][0].endswith("/containment/isolate_host")


def test_ticket_id_follows_incident():
    from core import data
    assert data.ticket_id({"alert_id": "ALR-1"}) == "TKT-ALR-1"
    assert data.ticket_id({"alert_id": "ALR-1", "incident_id": "INC-0003"}) == "TKT-INC-0003"
    assert data.contain("block_ioc", "1.2.3.4", "x", ticket="TKT-ALR-1")["ticket_id"] == "TKT-ALR-1"
