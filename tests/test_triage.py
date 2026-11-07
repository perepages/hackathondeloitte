import json
import pytest
import triage
import verdict


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

    result = triage.analyze_alert("ALR-1", use_llm=False)

    assert result.alert.alert_id == "ALR-1"
    assert result.verdict == "needs_more_info"
    assert result.severity == "high"  # medium x high asset, plus privileged user
    assert {item.kind for item in result.contexts} >= {"asset", "user", "intel"}
    assert result.related_logs[0]["event_id"] == "EDR-123"
    assert result.queries
    assert result.ticket is not None
    assert result.ticket["ticket_id"] == "TCK-ALR-1"


def test_analyze_alert_with_llm_mock(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-06T10:00:00Z",
            "source_product": "PROXY",
            "rule_name": "Beaconing a dominio sospechoso",
            "severity": "medium",
            "entities": {"domains": ["c2-bad.example"]},
            "evidence": {},
            "related_events": [],
        },
    )
    import ollama
    monkeypatch.setattr(
        ollama,
        "chat",
        lambda **kwargs: {
            "message": {
                "content": json.dumps({
                    "verdict": "true_positive",
                    "confidence": 0.95,
                    "rationale": "Dominio de C2 malicioso confirmado por análisis LLM.",
                    "summary": "Tráfico C2 detectado hacia infraestructura de atacante.",
                    "recommended_actions": [
                        {
                            "action": "block_ioc",
                            "target": "c2-bad.example",
                            "requires_approval": False,
                            "justification": "Bloqueo IOC C2",
                        }
                    ],
                    "escalation": {"escalate": True, "to": "N2", "reason": "C2 activo"},
                })
            }
        },
    )

    result = triage.analyze_alert("ALR-LLM-1", use_llm=True, model="llama3")

    assert result.verdict == "true_positive"
    assert "LLM" in result.verdict_rationale
    assert "llama" in result.decision_engine.lower()
    assert result.confidence == 0.95
    assert result.escalation.get("escalate") is True


def test_analyze_alert_identifies_benign_sccm_execution(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-05T07:56:30.000Z",
            "source_product": "EDR",
            "rule_id": "UC-EDR-002",
            "rule_name": "PowerShell con comando codificado",
            "severity": "medium",
            "entities": {
                "hosts": [{"hostname": "WS-BCN-1174", "ip": "10.10.1.185"}],
            },
            "evidence": {
                "parent": "CcmExec.exe (agente SCCM)",
                "user": "SYSTEM",
                "decoded_preview": "Get-CimInstance Win32_Product ... Out-File C:\\sw.json",
            },
            "related_events": ["EDR-0005329"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_asset",
        lambda key: {"hostname": key, "criticality": "Media", "business_service": "Puesto"},
    )
    monkeypatch.setattr(triage.soc_api, "search_changes", lambda query: [])
    monkeypatch.setattr(triage.soc_api, "search_logs", lambda *args, **kwargs: {"count": 0, "items": []})

    result = triage.analyze_alert("ALR-SCCM-1", use_llm=False)

    assert result.verdict == "benign_true_positive"
    assert "sccm" in result.verdict_rationale.lower() or "ccmexec" in result.verdict_rationale.lower()
    assert result.confidence >= 0.90
    assert result.escalation.get("escalate") is False


def test_analyze_alert_identifies_phishing_drill(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-05T12:13:18.693Z",
            "source_product": "EMAIL_GW",
            "rule_id": "UC-EML-001",
            "rule_name": "Correo reportado como phishing por un usuario",
            "severity": "low",
            "entities": {
                "users": [{"upn": "enric.fernandez@tarvia.example"}],
                "domains": ["tarvia.example"],
            },
            "evidence": {
                "sender": "rrhh@tarvia.example",
                "subject": "Simulacro de phishing: ¿lo has detectado?",
            },
            "related_events": [],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_user",
        lambda key: {"upn": key, "privileged": "False", "vip": "False"},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_intel",
        lambda ind: {"indicator": ind, "tip": None, "geo": None},
    )

    result = triage.analyze_alert("ALR-DRILL-1", use_llm=False)

    assert result.verdict == "benign_true_positive"
    assert "simulac" in result.verdict_rationale.lower()
    assert result.escalation.get("escalate") is False


def test_analyze_alert_identifies_malicious_tip_hit(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-06T01:18:09.000Z",
            "source_product": "NGFW",
            "rule_id": "UC-NET-002",
            "rule_name": "Conexión a IP en lista de bloqueo de TI",
            "severity": "high",
            "entities": {
                "hosts": [{"hostname": "JENKINS-DEV01", "ip": "10.60.1.10"}],
                "ips": ["141.94.96.144"],
            },
            "evidence": {
                "dst_ip": "141.94.96.144",
                "dst_port": 3333,
                "ti_match": "Pool de minería XMR",
                "action": "allow",
            },
            "related_events": ["FW-0025323"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_asset",
        lambda key: {"hostname": key, "criticality": "Alta", "business_service": "CI/CD"},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_intel",
        lambda ind: {
            "indicator": ind,
            "tip": {"category": "miner", "description": "XMR Mining Pool", "confidence": "high"},
            "geo": None,
        },
    )
    monkeypatch.setattr(triage.soc_api, "search_changes", lambda query: [])
    monkeypatch.setattr(triage.soc_api, "search_logs", lambda *args, **kwargs: {"count": 1, "items": []})

    result = triage.analyze_alert("ALR-MINER-1", use_llm=False)

    assert result.verdict == "true_positive"
    assert "tip" in result.verdict_rationale.lower() or "minería" in result.verdict_rationale.lower()
    assert result.confidence >= 0.90
    assert result.escalation.get("escalate") is True
    assert result.escalation.get("to") == "N2"
    assert any(act.get("action") == "block_ioc" for act in result.recommended_actions)


def test_analyze_alert_identifies_newsletter_false_positive(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-05T08:34:04.424Z",
            "source_product": "EMAIL_GW",
            "rule_id": "UC-EML-001",
            "rule_name": "Correo reportado como phishing por un usuario",
            "severity": "low",
            "entities": {
                "users": [{"upn": "alejandro.ruiz@tarvia.example"}],
                "domains": ["news.zalando.example"],
            },
            "evidence": {
                "sender": "newsletter@news.zalando.example",
                "subject": "Novedades de la semana",
            },
            "related_events": ["EML-0002728"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_user",
        lambda key: {"upn": key, "privileged": "False", "vip": "False"},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_intel",
        lambda ind: {"indicator": ind, "tip": None, "geo": None},
    )
    monkeypatch.setattr(triage.soc_api, "search_logs", lambda *args, **kwargs: {"count": 0, "items": []})

    result = triage.analyze_alert("ALR-ZALANDO-1", use_llm=False)

    assert result.verdict == "false_positive"
    assert "boletín" in result.verdict_rationale.lower() or "legítim" in result.verdict_rationale.lower()
    assert result.escalation.get("escalate") is False


def test_analyze_alert_identifies_phishing_link_click(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-07T08:35:15.000Z",
            "source_product": "EMAIL_GW",
            "rule_id": "UC-EML-003",
            "rule_name": "Clic en URL de phishing",
            "severity": "high",
            "entities": {
                "users": [{"upn": "laura.ferrer2@tarvia.example"}],
                "domains": ["tarvia-sso-login.example"],
            },
            "evidence": {
                "rewrite_verdict_now": "phishing",
            },
            "related_events": ["CLK-001"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_user",
        lambda key: {"upn": key, "privileged": "False", "vip": "False"},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_intel",
        lambda ind: {"indicator": ind, "tip": None, "geo": None},
    )
    monkeypatch.setattr(triage.soc_api, "search_logs", lambda *args, **kwargs: {"count": 1, "items": []})

    result = triage.analyze_alert("ALR-CLICK-1", use_llm=False)

    assert result.verdict == "true_positive"
    assert result.escalation.get("escalate") is True
    assert result.escalation.get("to") == "N2"
    actions = {a["action"] for a in result.recommended_actions}
    assert "revoke_sessions" in actions
    assert "reset_password" in actions


def test_analyze_alert_identifies_mfa_fatigue(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-10T21:50:34.000Z",
            "source_product": "IDP",
            "rule_id": "UC-IDP-003",
            "rule_name": "Fatiga MFA (bombardeo de notificaciones push)",
            "severity": "high",
            "entities": {
                "users": [{"upn": "sergio.navarro@tarvia.example"}],
                "ips": ["198.51.100.201"],
            },
            "evidence": {
                "push_requests": 27,
                "final_result": "approved",
                "src_city": "Madrid (VPN comercial)",
            },
            "related_events": ["SIGN-0084050"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_user",
        lambda key: {"upn": key, "privileged": "False", "vip": "False"},
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_intel",
        lambda ind: {"indicator": ind, "tip": None, "geo": None},
    )
    monkeypatch.setattr(triage.soc_api, "search_logs", lambda *args, **kwargs: {"count": 1, "items": []})

    result = triage.analyze_alert("ALR-MFA-1", use_llm=False)

    assert result.verdict == "true_positive"
    assert result.escalation.get("escalate") is True
    assert any(a["action"] == "revoke_sessions" for a in result.recommended_actions)


def test_analyze_alert_identifies_hr_notified_travel(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-09T13:12:29.697Z",
            "source_product": "IDP",
            "rule_id": "UC-IDP-001",
            "rule_name": "Viaje imposible",
            "severity": "medium",
            "entities": {
                "users": [{"upn": "elena.ferrer@tarvia.example"}],
                "ips": ["198.18.58.60"],
            },
            "evidence": {
                "current_login": {"city": "París", "ip": "198.18.58.60"},
            },
            "related_events": ["SIGN-0018332"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_user",
        lambda key: {
            "upn": key,
            "privileged": "False",
            "vip": "False",
            "hr_events": [
                {"tipo": "Viaje internacional", "detalle": "Reunión de compras en París"}
            ],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_intel",
        lambda ind: {"indicator": ind, "tip": None, "geo": None},
    )
    monkeypatch.setattr(triage.soc_api, "search_logs", lambda *args, **kwargs: {"count": 1, "items": []})

    result = triage.analyze_alert("ALR-TRAVEL-1", use_llm=False)

    assert result.verdict == "benign_true_positive"
    assert "viatge" in result.verdict_rationale.lower() or "viaje" in result.verdict_rationale.lower()
    assert result.escalation.get("escalate") is False


def test_analyze_alert_identifies_unauthorized_ot_access(monkeypatch):
    monkeypatch.setattr(
        triage.soc_api,
        "get_alert",
        lambda alert_id: {
            "alert_id": alert_id,
            "created_at": "2026-10-15T10:00:00Z",
            "source_product": "NGFW",
            "rule_id": "UC-OT-001",
            "rule_name": "Acceso no autorizado a red OT",
            "severity": "critical",
            "entities": {
                "hosts": [{"hostname": "WS-BCN-9999"}],
            },
            "evidence": {"dst_zone": "LOGISTICS-OT", "dst_port": 502},
            "related_events": ["FW-999"],
        },
    )
    monkeypatch.setattr(
        triage.soc_api,
        "get_asset",
        lambda key: {"hostname": key, "criticality": "Critica", "business_service": "OT"},
    )
    monkeypatch.setattr(triage.soc_api, "search_changes", lambda query: [])
    monkeypatch.setattr(triage.soc_api, "search_logs", lambda *args, **kwargs: {"count": 1, "items": []})

    result = triage.analyze_alert("ALR-OT-1", use_llm=False)

    assert result.verdict == "true_positive"
    assert result.escalation.get("escalate") is True
    assert "Operaciones" in result.escalation.get("to", "")
    assert not any(a["action"] == "isolate_host" for a in result.recommended_actions)
