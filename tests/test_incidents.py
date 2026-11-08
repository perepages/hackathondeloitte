"""incidents.py: alertas distintas de la misma intrusión en un único incidente (nivel 2, política §5 y §6)."""
import json
from pathlib import Path

import pytest

import incidents


def _row(n, rule, when, verdict="true_positive", decision="escalate", severity="medium", tactic="Execution", **ent):
    alert = {"alert_id": f"ALR-T-{n:06d}", "rule_id": rule, "rule_name": rule, "created_at": when,
             "entities": {k: v for k, v in ent.items() if k != "evidence"}, "evidence": ent.get("evidence") or {},
             "mitre": {"tactic": tactic}}
    return {"alert": alert, "verdict": verdict, "decision": decision, "severity": severity}


def test_reglas_distintas_con_la_misma_ip_externa_son_una_cadena_y_se_escala():
    rows = [_row(1, "UC-AI-001", "2026-10-08T20:13:00Z", decision="close", severity="low", ips=["198.19.95.151"]),
            _row(2, "UC-AI-002", "2026-10-08T20:20:00Z", severity="high", ips=["198.19.95.151"]),
            _row(3, "UC-AI-001", "2026-10-12T19:38:00Z", decision="close", severity="low", ips=["198.19.95.151"])]
    incs = incidents.apply(rows)
    assert len(incs) == 1 and incs[0]["count"] == 3 and incs[0]["chain"]
    assert incs[0]["decision"] == "escalate" and incs[0]["severity"] == "high"
    assert all(r["decision"] == "escalate" and r["incident_id"] == incs[0]["incident_id"] for r in rows)
    assert rows[0]["escalated_by_incident"] and "§5" in rows[0]["decision_notes"][-1]


def test_la_misma_regla_repetida_no_es_cadena_y_no_fuerza_escalar():
    rows = [_row(i, "UC-WEB-001", f"2026-10-0{i}T10:00:00Z", decision="close", severity="low", ips=["203.0.113.9"])
            for i in range(1, 4)]
    incs = incidents.apply(rows)
    assert len(incs) == 1 and not incs[0]["chain"] and incs[0]["decision"] == "close"
    assert all(r["decision"] == "close" for r in rows)


def test_el_mismo_equipo_solo_une_en_48_horas():
    near = [_row(1, "UC-EDR-001", "2026-10-09T09:00:00Z", hosts=[{"hostname": "WS-1"}]),
            _row(2, "UC-NET-001", "2026-10-10T20:00:00Z", hosts=[{"hostname": "WS-1"}])]
    far = [_row(1, "UC-EDR-001", "2026-10-01T09:00:00Z", hosts=[{"hostname": "WS-1"}]),
           _row(2, "UC-NET-001", "2026-10-09T09:00:00Z", hosts=[{"hostname": "WS-1"}])]
    assert len(incidents.build(near)) == 1
    assert incidents.build(far) == []


def test_la_misma_cuenta_une_dias_despues_aunque_se_escriba_distinto():
    rows = [_row(1, "UC-NET-004", "2026-10-10T00:42:00Z", users=[{"upn": "adm.aortega@tarvia.example"}]),
            _row(2, "UC-IDP-008", "2026-10-18T01:16:00Z", evidence={"by": "adm.aortega"},
                 users=[{"upn": "adm.aortega@tarvia.example"}]),
            _row(3, "UC-EDR-011", "2026-10-18T01:22:00Z", hosts=[{"hostname": "PRINT01"}],
                 evidence={"user": "TARVIA\\adm.aortega"})]
    incs = incidents.build(rows)
    assert len(incs) == 1 and incs[0]["count"] == 3


def test_lo_autorizado_y_las_falsas_alarmas_no_forman_incidentes():
    rows = [_row(i, "UC-WEB-001", f"2026-10-08T0{i}:00:00Z", verdict="benign_true_positive", decision="close",
                 ips=["192.0.2.10"]) for i in range(1, 5)]
    rows += [_row(9, "UC-EML-001", "2026-10-08T09:00:00Z", verdict="false_positive", decision="close",
                  ips=["192.0.2.10"])]
    assert incidents.build(rows) == []


def test_lo_propio_y_lo_legitimo_no_une():
    rows = [_row(1, "UC-EML-001", "2026-10-08T09:00:00Z", domains=["tarvia.example", "login.microsoft.com"],
                 evidence={"legit_supplier_domain": "proveidor.example", "body": "veure proveidor.example"}),
            _row(2, "UC-NET-001", "2026-10-08T10:00:00Z", domains=["www.tarvia.example", "microsoft.com"],
                 evidence={"note": "proveidor.example"})]
    assert incidents.build(rows) == []


def test_las_pistas_demasiado_populares_no_unen(monkeypatch):
    monkeypatch.setenv("SOC_INCIDENT_HUB", "3")
    rows = [_row(i, f"UC-R-{i}", f"2026-10-08T0{i}:00:00Z", hosts=[{"hostname": "JUMP01"}]) for i in range(1, 6)]
    assert incidents.build(rows) == []


def test_ni_nombres_de_cuenta_ni_ficheros_son_dominios():
    p = incidents.pivots({"evidence": {"account": "adm.aortega", "postinstall": "node install.mjs", "f": "sw.json",
                                       "network": "POST a npm-telemetry-stats.example"}})
    assert ("domini", "npm-telemetry-stats.example") in p
    assert not any(k == "domini" and v in ("adm.aortega", "install.mjs", "sw.json") for k, v in p)


# ----------------------------------------------------------------------------- escenarios reales del reto

DATASET = Path(__file__).resolve().parents[2] / "DTT-UAB-The-Hack" / "03_alertas" / "alertas.jsonl"
BENIGN = set(range(11830, 11873)) | {11873, 11876, 11915, 11922} | set(range(11916, 11922))


@pytest.fixture(scope="module")
def scenario():
    if not DATASET.exists():
        pytest.skip("dataset del reto no disponible")
    rows = []
    for line in DATASET.read_text(encoding="utf-8").splitlines():
        a = json.loads(line)
        n = int(a["alert_id"][-6:])
        if n >= 11785:  # las alertas de escenario; veredicto esperado (lo que hace bien el triaje con la IA)
            ok = n not in BENIGN
            rows.append({"alert": a, "verdict": "true_positive" if ok else "benign_true_positive",
                         "decision": "escalate" if ok else "close", "severity": a["severity"]})
    by = {}
    for inc in incidents.build(rows):
        for i in inc["alert_ids"]:
            by[int(i[-6:])] = inc
    return by


@pytest.mark.parametrize("members,name", [
    (range(11790, 11799), "intrusión WS-BCN-1770 → FS01"),
    ((11790, 11895, 11896), "vuelve 8 días después a PRINT01 con adm.aortega"),
    (range(11902, 11915), "campaña de la factura falsa + robo de sesión tras el clic"),
    (range(11897, 11901), "RAM scraper en los TPV + su C2"),
    (range(11822, 11825), "atacante del asistente Vela"),
    (range(11786, 11790), "BEC de Laura Ferrer"),
    (range(11819, 11822), "claves cloud robadas"),
])
def test_escenarios_que_deben_ir_juntos(scenario, members, name):
    ids = {scenario[n]["incident_id"] for n in members if n in scenario}
    assert len(ids) == 1 and all(n in scenario for n in members), name


def test_lo_autorizado_del_reto_no_forma_incidentes(scenario):
    assert not BENIGN & set(scenario)


def test_ataques_distintos_no_se_mezclan(scenario):
    assert scenario[11790]["incident_id"] != scenario[11897]["incident_id"]  # intrusión ≠ TPV
    assert scenario[11883]["incident_id"] != scenario[11902]["incident_id"]  # túnel DNS ≠ phishing
