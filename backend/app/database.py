"""Small SQLite persistence layer; no network database is required."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .config import DATABASE_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    message TEXT NOT NULL,
    host TEXT,
    occurred_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('system', 'network')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    result TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved')),
    description TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(event_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at DESC);
"""


def connect() -> sqlite3.Connection:
    path = Path(DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


@contextmanager
def session() -> Iterator[sqlite3.Connection]:
    connection = connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    with session() as connection:
        connection.executescript(SCHEMA)


def row_to_event(row: sqlite3.Row) -> dict:
    event = dict(row)
    event["metadata"] = json.loads(event["metadata"])
    return event


def create_scan(scan_id: str, scan_type: str, target: str, started_at: str) -> None:
    with session() as connection:
        connection.execute(
            "INSERT INTO scans (id, scan_type, status, target, started_at) VALUES (?, ?, 'queued', ?, ?)",
            (scan_id, scan_type, target, started_at),
        )


def update_scan(scan_id: str, *, status: str, result: dict | None = None, error: str | None = None, completed_at: str | None = None) -> None:
    with session() as connection:
        connection.execute(
            "UPDATE scans SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?",
            (status, json.dumps(result, separators=(",", ":"), ensure_ascii=False) if result is not None else None, error, completed_at, scan_id),
        )


def row_to_scan(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["result"] = json.loads(item["result"]) if item["result"] else None
    return item

def create_alert(
    alert_id: str, event_id: str, rule_id: str, title: str, severity: str,
    description: str, created_at: str,
) -> None:
    with session() as connection:
        connection.execute(
            """INSERT OR IGNORE INTO alerts
            (id, event_id, rule_id, title, severity, status, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?)""",
            (alert_id, event_id, rule_id, title, severity, description, created_at, created_at),
        )


def list_alerts(status: str | None, limit: int) -> list[sqlite3.Row]:
    with session() as connection:
        if status:
            return connection.execute(
                "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return connection.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()


def update_alert(alert_id: str, status: str, updated_at: str) -> sqlite3.Row | None:
    with session() as connection:
        connection.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, updated_at, alert_id),
        )
        return connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()


def row_to_alert(row: sqlite3.Row) -> dict:
    return dict(row)
