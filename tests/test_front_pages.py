"""Cada página del front se ejecuta sin errores con el fixture (no necesita la API).

    .venv\\Scripts\\python.exe -m pytest -q tests/test_front_pages.py
"""
import os

import pytest
from streamlit.testing.v1 import AppTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app.py")
PAGES = ["views/inicio.py", "views/cola.py", "views/ticket.py", "views/contencion.py",
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
    assert any("esperan a una persona" in s.value for s in at.success)


def test_cola_review_is_saved():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.session_state["cola_open"] = "ALR-20261006-011826"  # abre la ficha de una alerta escalada
    at.switch_page("views/cola.py").run()
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
        assert any("Hecha" in s.value for s in at.success)


@pytest.mark.parametrize("page", PAGES)
def test_paginas_en_modo_live_sin_alertas(page, monkeypatch):
    """Así se arranca el día de la defensa: modo live y ninguna alerta triada todavía."""
    from core import data
    monkeypatch.setattr(data, "MODE", "live")
    monkeypatch.setattr(data, "suggest_ids", lambda n=10: [])  # sin depender de la API de Deloitte
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.switch_page(page).run()
    assert not at.exception, at.exception


def test_cola_bandeja_y_ficha():
    """Una sola pantalla: la bandeja filtra por gravedad y la ficha de la alerta abierta sale debajo."""
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.switch_page("views/cola.py").run()
    assert not at.exception, at.exception
    assert at.text_input(key="cola_analyst")  # ficha visible sin cambiar de pantalla (la más urgente)
    at.multiselect(key="cola_sev").set_value(["high"]).run()
    assert not at.exception, at.exception
    assert any("de 150 alertas" in c.value for c in at.caption)
    at.session_state["cola_open"] = "ALR-20261020-011905"
    at.run()
    assert not at.exception, at.exception
    assert any("engañar al sistema" in e.value for e in at.error)


def test_contencion_tarjetas():
    """Acciones de respuesta: se elige la alerta con tarjetas, sin desplegable."""
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.switch_page("views/contencion.py").run()
    assert not at.exception, at.exception
    btns = [b for b in at.button if b.key and b.key.startswith("contencion_pick_btn_") and not b.disabled]
    assert btns
    btns[0].click().run()
    assert not at.exception, at.exception
