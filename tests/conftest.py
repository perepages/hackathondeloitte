import os

import pytest

# Los tests corren siempre sobre la muestra, aunque el .env de quien los lance diga SOC_MODE=live
# (load_dotenv no pisa una variable que ya existe).
os.environ.setdefault("SOC_MODE", "fixture")


@pytest.fixture(autouse=True)
def _sin_llm_por_defecto(monkeypatch):
    """Los tests no llaman a la pasarela LLM: el veredicto sale de las reglas salvo que un test diga otra cosa."""
    monkeypatch.setenv("SOC_VERDICT_ENGINE", "rules")
