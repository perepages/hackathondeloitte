import triage


def test_analyze_alert_gathers_context_and_keeps_unconfirmed_verdict(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-05T10:00:00Z",
            "source_product": "EDR",
            "rule_name": "PowerShell encoded",
            "severity": "medium",
            "entities": {
                "hosts": [{"hostname": "WS-1", "ip": "10.0.0.1"}],
                "users": [{"upn": "analyst@example.test"}],
                "ips": ["198.51.100.10"],
            },
            "evidence": {},
            "related_events": ["EDR-123"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_asset",
        lambda key: {"hostname": key, "criticality": "Alta", "business_service": "Test"},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_user",
        lambda key: {"upn": key, "privileged": "True", "vip": "False"},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_intel",
        lambda indicator: {"indicator": indicator, "tip": None, "geo": None},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "search_logs",
        lambda *args, **kwargs: {"count": 1, "truncated": False, "items": [{"event_id": "EDR-123"}]},
    )
    monkeypatch.setattr(triage.soc_api, "search_changes", lambda query: [])

    result = triage.analyze_alert("ALR-1")

    assert result.alert.alert_id == "ALR-1"
    assert result.verdict == "needs_more_info"  # regla sin lógica N1: las reglas no se atreven
    assert result.decision == "escalate"  # needs_more_info de gravedad media o más: escalado obligatorio
    assert result.decision_source == "rules"
    assert result.severity == "high"  # medium x high asset, plus privileged user
    assert {item.kind for item in result.contexts} >= {"asset", "user", "intel"}
    assert result.related_logs[0]["event_id"] == "EDR-123"
    assert result.queries


def test_sin_equipo_en_la_alerta_usa_el_puesto_del_usuario(monkeypatch):
    """Política §2: la matriz se cruza con el activo o identidad más crítica afectada (aquí, su portátil)."""
    monkeypatch.setattr(triage.soc_api, "get_alert", lambda alert_id: {
        "alert_id": alert_id, "created_at": "2026-10-05T10:00:00Z", "source_product": "EMAIL_GW",
        "rule_id": "UC-EML-001", "rule_name": "Correo reportado", "severity": "low",
        "entities": {"users": [{"upn": "ceo@example.test"}]}, "evidence": {"sender": "x@news.example"},
        "related_events": []})
    monkeypatch.setattr(triage.soc_api, "get_user", lambda key: {
        "upn": key, "privileged": "False", "vip": "False", "workstation": "WS-CEO"})
    monkeypatch.setattr(triage.soc_api, "get_asset", lambda key: {
        "hostname": key, "criticality": "Crítica", "zone": "HQ-USERS"})
    monkeypatch.setattr(triage.soc_api, "get_intel", lambda indicator: {"indicator": indicator, "tip": None, "geo": None})
    monkeypatch.setattr(triage.soc_api, "search_changes", lambda query: [])

    result = triage.analyze_alert("ALR-2", decide=False)

    assert result.severity == "medium"  # low x Crítica
    assert "WS-CEO" in result.severity_rationale and "puesto de trabajo" in result.severity_rationale
