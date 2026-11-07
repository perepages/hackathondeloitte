import pytest


@pytest.fixture(autouse=True)
def _sin_llm_por_defecto(monkeypatch):
    """Los tests no llaman a la pasarela LLM: el veredicto sale de las reglas salvo que un test diga otra cosa."""
    monkeypatch.setenv("SOC_VERDICT_ENGINE", "rules")
