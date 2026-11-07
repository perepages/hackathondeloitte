import unicodedata


SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
CRITICALITY_ORDER = ("baja", "media", "alta", "critica")

# Operational severity matrix from 01_contexto/politica_soc.md.
_MATRIX = {
    "informational": ("informational", "informational", "low", "low"),
    "low": ("informational", "low", "low", "medium"),
    "medium": ("low", "medium", "medium", "high"),
    "high": ("medium", "high", "high", "critical"),
    "critical": ("high", "critical", "critical", "critical"),
}


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.strip().lower())
    return "".join(char for char in normalized if not unicodedata.combining(char))


def base_severity(rule_severity: str, asset_criticality: str) -> str:
    """Cross the SIEM rule severity with the most critical affected asset."""
    rule = _normalize(rule_severity)
    criticality = _normalize(asset_criticality)
    if rule not in _MATRIX:
        raise ValueError(f"Severidad de regla desconocida: {rule_severity!r}")
    try:
        column = CRITICALITY_ORDER.index(criticality)
    except ValueError as exc:
        raise ValueError(f"Criticidad de activo desconocida: {asset_criticality!r}") from exc
    return _MATRIX[rule][column]


def apply_severity_adjustment(severity: str, adjustment: int) -> str:
    """Apply at most one policy adjustment (+1, -1, or 0), clamped to bounds."""
    normalized = _normalize(severity)
    if normalized not in SEVERITY_ORDER:
        raise ValueError(f"Severidad desconocida: {severity!r}")
    if adjustment not in (-1, 0, 1):
        raise ValueError("El ajuste de severidad debe ser -1, 0 o 1")
    index = SEVERITY_ORDER.index(normalized)
    adjusted_index = max(0, min(len(SEVERITY_ORDER) - 1, index + adjustment))
    return SEVERITY_ORDER[adjusted_index]
