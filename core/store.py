"""Decisiones de la persona, guardadas en SQLite (dueño: persona B).

data/soc.db no se sube a git (*.db está en .gitignore).
"""
from __future__ import annotations

import datetime as dt
import os
import sqlite3

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "soc.db")


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS reviews (
        alert_id TEXT PRIMARY KEY, decision TEXT NOT NULL, analyst TEXT NOT NULL,
        note TEXT DEFAULT '', at TEXT NOT NULL)""")
    return c


def save_review(alert_id: str, decision: str, analyst: str, note: str = "") -> None:
    """decision: 'close' o 'escalate'."""
    at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO reviews VALUES (?, ?, ?, ?, ?)", (alert_id, decision, analyst, note, at))


def delete_review(alert_id: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM reviews WHERE alert_id = ?", (alert_id,))


def list_reviews() -> dict[str, dict]:
    with _conn() as c:
        rows = c.execute("SELECT alert_id, decision, analyst, note, at FROM reviews").fetchall()
    return {r[0]: {"decision": r[1], "analyst": r[2], "note": r[3], "at": r[4]} for r in rows}


def get_review(alert_id: str) -> dict | None:
    return list_reviews().get(alert_id)
