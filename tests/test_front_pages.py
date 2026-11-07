"""Cada página del front se ejecuta sin errores con el fixture (no necesita la API).

    .venv\\Scripts\\python.exe -m pytest -q tests/test_front_pages.py
"""
import os

import pytest
from streamlit.testing.v1 import AppTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app.py")
PAGES = ["views/cola.py", "views/ticket.py", "views/contencion.py",
         "views/directo.py", "views/panel.py", "views/incidentes.py"]


@pytest.fixture(autouse=True)
def _fixture_mode(monkeypatch, tmp_path):
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("SOC_MODE", "fixture")
    from core import store
    monkeypatch.setattr(store, "DB", str(tmp_path / "soc.db"))


@pytest.mark.parametrize("page", PAGES)
def test_page_runs(page):
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception, at.exception
    at.switch_page(page).run()
    assert not at.exception, at.exception


def test_directo_runs_sample_batch():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.switch_page("views/directo.py").run()
    at.button(key="directo_go").click().run()
    assert not at.exception, at.exception
    assert any("esperan a la persona" in s.value for s in at.success)


def test_cola_review_is_saved():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input(key="cola_analyst").input("Ana").run()
    at.button(key="cola_ok").click().run()
    assert not at.exception, at.exception
    assert any("Ana" in s.value for s in at.success)


def test_ticket_cumple_esquema_para_todas_las_alertas():
    """El ticket de cualquier alerta del fixture valida contra el esquema de Deloitte.

    Carga solo las funciones de views/ticket.py (la parte de arriba, antes de pintar la página)."""
    from core import data
    path = os.path.join(ROOT, "views", "ticket.py")
    src = open(path, encoding="utf-8").read().split("\nrows = data.load_results()")[0]
    ns: dict = {}
    exec(compile(src, path, "exec"), ns)
    errors = [(r["alert_id"], ns["validate"](ns["build_ticket"](r))) for r in data._load_fixture()]
    bad = [e for e in errors if e[1] not in (None, "sin-esquema")]
    assert not bad, bad[:3]


def test_contencion_aprobar_y_ejecutar():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.switch_page("views/contencion.py").run()
    assert not at.exception, at.exception
    runs = [b for b in at.button if b.key and b.key.startswith("contencion_run_")]
    if runs:
        runs[0].click().run()
        assert not at.exception, at.exception
        assert any("Ejecutada" in s.value for s in at.success)
