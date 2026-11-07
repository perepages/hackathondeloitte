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


def test_severity_adjustment_moves_at_most_one_level():
    assert apply_severity_adjustment("medium", 1) == "high"
    assert apply_severity_adjustment("medium", -1) == "low"


def test_severity_adjustment_stays_within_severity_range():
    assert apply_severity_adjustment("critical", 1) == "critical"
    assert apply_severity_adjustment("informational", -1) == "informational"


def test_severity_adjustment_rejects_more_than_one_level():
    with pytest.raises(ValueError):
        apply_severity_adjustment("medium", 2)
