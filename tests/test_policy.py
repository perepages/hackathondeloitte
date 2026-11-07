import pytest

from policy import apply_severity_adjustment, base_severity


@pytest.mark.parametrize(
    ("rule_severity", "asset_criticality", "expected"),
    [
        ("informational", "Baja", "informational"),
        ("low", "Media", "low"),
        ("medium", "Alta", "medium"),
        ("critical", "Baja", "high"),
        ("high", "Crítica", "critical"),
    ],
)
def test_base_severity_uses_soc_matrix(rule_severity, asset_criticality, expected):
    assert base_severity(rule_severity, asset_criticality) == expected


def test_matriz_identica_a_la_politica_de_deloitte():
    """Las 20 celdas de policy.py contra la tabla de 01_contexto/politica_soc.md (si el dataset está al lado)."""
    import os
    import re
    path = os.path.join(os.path.dirname(__file__), "..", "..", "DTT-UAB-The-Hack", "01_contexto", "politica_soc.md")
    if not os.path.exists(path):
        pytest.skip("dataset de Deloitte no disponible")
    text = open(path, encoding="utf-8").read().split("## 2.", 1)[1].split("## 3.", 1)[0]  # solo la matriz
    rows = re.findall(r"^\| (informational|low|medium|high|critical) \|(.+)\|$", text, re.M)
    assert len(rows) == 5
    for rule, cells in rows:
        for criticality, expected in zip(("Baja", "Media", "Alta", "Crítica"), [c.strip() for c in cells.split("|")]):
            assert base_severity(rule, criticality) == expected, (rule, criticality)


def test_activo_afectado_cuando_la_alerta_no_trae_equipo():
    from policy import cloud_asset, service_assets
    waf = {"source_product": "WAF", "entities": {"urls": ["https://www.tarvia.example/wp-login.php"]}}
    assert service_assets(waf)[0][0] == "WEB-ECOM01"
    assert service_assets({"source_product": "AI_GATEWAY", "entities": {}})[0][0] == "AI-ASSIST01"
    bucket = {"entities": {"cloud": {"bucket": "tarvia-backups-prod"}},
              "evidence": {"bucket_classification": "Crítica (copias del CRM)"}}
    assert cloud_asset(bucket)["criticality"] == "Crítica"
    assert cloud_asset({"entities": {"cloud": {"bucket": "tarvia-backups-prod"}}})["criticality"] == "Alta"


def test_severity_adjustment_moves_at_most_one_level():
    assert apply_severity_adjustment("medium", 1) == "high"
    assert apply_severity_adjustment("medium", -1) == "low"


def test_severity_adjustment_stays_within_severity_range():
    assert apply_severity_adjustment("critical", 1) == "critical"
    assert apply_severity_adjustment("informational", -1) == "informational"


def test_severity_adjustment_rejects_more_than_one_level():
    with pytest.raises(ValueError):
        apply_severity_adjustment("medium", 2)
