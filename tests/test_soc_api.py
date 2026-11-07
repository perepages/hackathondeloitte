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
