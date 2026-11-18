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
    error TEXT,
    progress TEXT
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
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
 status TEXT NOT NULL CHECK (status IN ('open','investigating','contained','resolved','closed')),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cases_status_updated ON cases(status, updated_at DESC);
CREATE TABLE IF NOT EXISTS case_events (
 case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
 event_id TEXT NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
 linked_at TEXT NOT NULL, PRIMARY KEY(case_id,event_id)
);
CREATE TABLE IF NOT EXISTS case_timeline (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
 entry_type TEXT NOT NULL, actor TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}',
 occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_timeline_case ON case_timeline(case_id,id DESC);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_occurred ON audit_log(occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id, id DESC);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    original_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    content_type TEXT,
    source TEXT NOT NULL DEFAULT 'local-upload',
    storage_path TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('acquired','verified','tampered','missing','released')),
    acquired_at TEXT NOT NULL,
    acquired_by TEXT NOT NULL DEFAULT 'local',
    last_verified_at TEXT,
    verify_count INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_sha ON evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id, acquired_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_acquired ON evidence(acquired_at DESC);
CREATE TABLE IF NOT EXISTS evidence_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_custody_evidence ON evidence_custody(evidence_id, id DESC);
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
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        if "progress" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN progress TEXT")


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


def delete_system_scan(scan_id: str, deleted_at: str) -> dict | None:
    """Delete one completed/failed host scan while retaining an audit record."""
    with session() as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None or row["scan_type"] != "system" or row["status"] in {"queued", "running"}:
            return None
        snapshot = dict(row)
        append_audit(
            connection, "scan", scan_id, "scan.deleted", deleted_at,
            {"scan_type": row["scan_type"], "status": row["status"],
             "target": row["target"], "started_at": row["started_at"]},
        )
        connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return snapshot


def delete_completed_system_scans(deleted_at: str) -> int:
    """Clear completed/failed host scan history only; active and network scans remain."""
    with session() as connection:
        rows = connection.execute(
            "SELECT id, status, target, started_at FROM scans "
            "WHERE scan_type = 'system' AND status IN ('completed', 'failed')"
        ).fetchall()
        if not rows:
            return 0
        append_audit(
            connection, "scan", "system", "scan.history_cleared", deleted_at,
            {"deleted_count": len(rows)},
        )
        connection.execute(
            "DELETE FROM scans WHERE scan_type = 'system' AND status IN ('completed', 'failed')"
        )
        return len(rows)


def update_scan(
    scan_id: str, *, status: str, result: dict | None = None,
    error: str | None = None, completed_at: str | None = None,
    progress: dict | None = None,
) -> None:
    assignments = ["status = ?"]
    values: list[object] = [status]
    if result is not None:
        assignments.append("result = ?")
        values.append(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
    if error is not None:
        assignments.append("error = ?")
        values.append(error)
    if completed_at is not None:
        assignments.append("completed_at = ?")
        values.append(completed_at)
    if progress is not None:
        assignments.append("progress = ?")
        values.append(json.dumps(progress, separators=(",", ":"), ensure_ascii=False))
    values.append(scan_id)
    with session() as connection:
        connection.execute(
            "UPDATE scans SET " + ", ".join(assignments) + " WHERE id = ?", values
        )

def row_to_scan(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["result"] = json.loads(item["result"]) if item["result"] else None
    item["progress"] = json.loads(item["progress"]) if item.get("progress") else None
    return item

def append_audit(
    connection: sqlite3.Connection, entity_type: str, entity_id: str,
    action: str, occurred_at: str, details: dict | None = None,
    actor: str = "local",
) -> None:
    connection.execute(
        """INSERT INTO audit_log (entity_type, entity_id, action, actor, details, occurred_at)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (entity_type, entity_id, action, actor,
         json.dumps(details or {}, separators=(",", ":"), ensure_ascii=False), occurred_at),
    )


def list_audit_log(limit: int, entity_type: str | None = None) -> list[sqlite3.Row]:
    with session() as connection:
        if entity_type:
            return connection.execute(
                "SELECT * FROM audit_log WHERE entity_type = ? ORDER BY id DESC LIMIT ?",
                (entity_type, limit),
            ).fetchall()
        return connection.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def row_to_audit(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["details"] = json.loads(item["details"])
    return item


def create_alert(
    alert_id: str, event_id: str, rule_id: str, title: str, severity: str,
    description: str, created_at: str,
) -> None:
    with session() as connection:
        cursor = connection.execute(
            """INSERT OR IGNORE INTO alerts
            (id, event_id, rule_id, title, severity, status, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?)""",
            (alert_id, event_id, rule_id, title, severity, description, created_at, created_at),
        )
        if cursor.rowcount:
            append_audit(
                connection, "alert", alert_id, "alert.created", created_at,
                {"event_id": event_id, "rule_id": rule_id, "status": "open"},
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
        current = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if current is None:
            return None
        previous_status = current["status"]
        if previous_status != status:
            connection.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                (status, updated_at, alert_id),
            )
            append_audit(
                connection, "alert", alert_id, "alert.status_changed", updated_at,
                {"from": previous_status, "to": status},
            )
        return connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()


def row_to_alert(row: sqlite3.Row) -> dict:
    return dict(row)


def create_case(case_id: str, title: str, description: str, severity: str, created_at: str) -> sqlite3.Row:
    with session() as connection:
        connection.execute(
            "INSERT INTO cases (id,title,description,severity,status,created_at,updated_at) VALUES (?,?,?,?, 'open',?,?)",
            (case_id,title,description,severity,created_at,created_at),
        )
        details = {"title": title, "severity": severity}
        connection.execute(
            "INSERT INTO case_timeline (case_id,entry_type,actor,details,occurred_at) VALUES (?,'case.created','local',?,?)",
            (case_id,json.dumps(details,separators=(",",":")),created_at),
        )
        append_audit(connection,"case",case_id,"case.created",created_at,details)
        return connection.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone()


def list_cases(status: str | None, severity: str | None, limit: int) -> list[sqlite3.Row]:
    clauses, params = [], []
    if status:
        clauses.append("status=?")
        params.append(status)
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with session() as connection:
        return connection.execute(
            f"SELECT * FROM cases{where} ORDER BY updated_at DESC LIMIT ?", [*params,limit]
        ).fetchall()


def get_case(case_id: str) -> sqlite3.Row | None:
    with session() as connection:
        return connection.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone()


def update_case(case_id: str, changes: dict[str,str], updated_at: str) -> sqlite3.Row | None:
    allowed = {"title","description","severity","status"}
    if not changes or not set(changes).issubset(allowed):
        raise ValueError("Invalid case update fields.")
    with session() as connection:
        current = connection.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone()
        if current is None:
            return None
        actual = {k:v for k,v in changes.items() if current[k] != v}
        if actual:
            assignments = ", ".join(f"{key}=?" for key in actual)
            values = list(actual.values())
            if actual.get("status") in {"resolved","closed"}:
                assignments += ", closed_at=?"
                values.append(updated_at)
            elif actual.get("status") in {"open","investigating","contained"}:
                assignments += ", closed_at=NULL"
            values.extend([updated_at,case_id])
            connection.execute(f"UPDATE cases SET {assignments}, updated_at=? WHERE id=?",values)
            details = {"changes": {k: {"from": current[k], "to": v} for k,v in actual.items()}}
            connection.execute(
                "INSERT INTO case_timeline (case_id,entry_type,actor,details,occurred_at) VALUES (?,'case.updated','local',?,?)",
                (case_id,json.dumps(details,separators=(",",":")),updated_at),
            )
            append_audit(connection,"case",case_id,"case.updated",updated_at,details)
        return connection.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone()


def link_event_to_case(case_id: str, event_id: str, linked_at: str) -> bool:
    with session() as connection:
        if connection.execute("SELECT 1 FROM cases WHERE id=?",(case_id,)).fetchone() is None:
            return False
        if connection.execute("SELECT 1 FROM events WHERE id=?",(event_id,)).fetchone() is None:
            return False
        cursor = connection.execute(
            "INSERT OR IGNORE INTO case_events (case_id,event_id,linked_at) VALUES (?,?,?)",
            (case_id,event_id,linked_at),
        )
        if cursor.rowcount:
            details = {"event_id":event_id}
            connection.execute(
                "INSERT INTO case_timeline (case_id,entry_type,actor,details,occurred_at) VALUES (?,'event.linked','local',?,?)",
                (case_id,json.dumps(details,separators=(",",":")),linked_at),
            )
            append_audit(connection,"case",case_id,"case.event_linked",linked_at,details)
        return True


def add_case_note(case_id: str, content: str, created_at: str) -> bool:
    with session() as connection:
        if connection.execute("SELECT 1 FROM cases WHERE id=?",(case_id,)).fetchone() is None:
            return False
        details = {"content":content}
        connection.execute(
            "INSERT INTO case_timeline (case_id,entry_type,actor,details,occurred_at) VALUES (?,'note.added','local',?,?)",
            (case_id,json.dumps(details,separators=(",",":"),ensure_ascii=False),created_at),
        )
        append_audit(connection,"case",case_id,"case.note_added",created_at,{"content_length":len(content)})
        connection.execute("UPDATE cases SET updated_at=? WHERE id=?",(created_at,case_id))
        return True


def list_case_events(case_id: str) -> list[sqlite3.Row]:
    with session() as connection:
        return connection.execute(
            "SELECT e.*, ce.linked_at FROM events e JOIN case_events ce ON ce.event_id=e.id WHERE ce.case_id=? ORDER BY ce.linked_at ASC",
            (case_id,),
        ).fetchall()


def list_case_timeline(case_id: str, limit: int=500) -> list[sqlite3.Row]:
    with session() as connection:
        return connection.execute(
            "SELECT * FROM case_timeline WHERE case_id=? ORDER BY id DESC LIMIT ?",
            (case_id,limit),
        ).fetchall()


def row_to_case(row: sqlite3.Row) -> dict:
    return dict(row)


def row_to_case_timeline(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["details"] = json.loads(item["details"])
    return item


def _insert_custody(
    connection: sqlite3.Connection, evidence_id: str, action: str, actor: str,
    note: str, sha256: str, occurred_at: str,
) -> None:
    connection.execute(
        """INSERT INTO evidence_custody (evidence_id, action, actor, note, sha256, occurred_at)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, action, actor, note, sha256, occurred_at),
    )


def create_evidence(
    evidence_id: str, original_name: str, size_bytes: int, sha256: str,
    content_type: str | None, source: str, storage_path: str, acquired_at: str,
    case_id: str | None = None, note: str = "", actor: str = "local",
) -> sqlite3.Row:
    with session() as connection:
        connection.execute(
            """INSERT INTO evidence
            (id, case_id, original_name, size_bytes, sha256, content_type, source,
             storage_path, status, acquired_at, acquired_by, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'acquired', ?, ?, ?)""",
            (evidence_id, case_id, original_name, size_bytes, sha256, content_type,
             source, storage_path, acquired_at, actor, note),
        )
        _insert_custody(
            connection, evidence_id, "acquired", actor,
            f"Acquired {original_name} ({size_bytes} bytes) from {source}.",
            sha256, acquired_at,
        )
        append_audit(
            connection, "evidence", evidence_id, "evidence.acquired", acquired_at,
            {"sha256": sha256, "size_bytes": size_bytes, "source": source, "case_id": case_id},
            actor=actor,
        )
        if case_id:
            details = {"evidence_id": evidence_id, "sha256": sha256, "name": original_name}
            connection.execute(
                """INSERT INTO case_timeline (case_id, entry_type, actor, details, occurred_at)
                VALUES (?,'evidence.linked',?,?,?)""",
                (case_id, actor, json.dumps(details, separators=(",", ":")), acquired_at),
            )
            connection.execute("UPDATE cases SET updated_at=? WHERE id=?", (acquired_at, case_id))
        return connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()


def find_evidence_by_sha(sha256: str) -> sqlite3.Row | None:
    with session() as connection:
        return connection.execute(
            "SELECT * FROM evidence WHERE sha256=? ORDER BY acquired_at ASC LIMIT 1", (sha256,)
        ).fetchone()


def get_evidence(evidence_id: str) -> sqlite3.Row | None:
    with session() as connection:
        return connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()


def list_evidence(
    case_id: str | None, sha256: str | None, status: str | None, limit: int, offset: int,
) -> tuple[list[sqlite3.Row], int]:
    clauses: list[str] = []
    params: list[object] = []
    if case_id:
        clauses.append("case_id=?")
        params.append(case_id)
    if sha256:
        clauses.append("sha256=?")
        params.append(sha256)
    if status:
        clauses.append("status=?")
        params.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with session() as connection:
        total = connection.execute(f"SELECT COUNT(*) FROM evidence{where}", params).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM evidence{where} ORDER BY acquired_at DESC, id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return rows, total


def list_evidence_custody(evidence_id: str, limit: int = 200) -> list[sqlite3.Row]:
    with session() as connection:
        return connection.execute(
            "SELECT * FROM evidence_custody WHERE evidence_id=? ORDER BY id DESC LIMIT ?",
            (evidence_id, limit),
        ).fetchall()


def add_custody_entry(
    evidence_id: str, action: str, actor: str, note: str, occurred_at: str,
) -> sqlite3.Row | None:
    with session() as connection:
        row = connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            return None
        if action == "released":
            connection.execute(
                "UPDATE evidence SET status='released' WHERE id=?", (evidence_id,)
            )
        _insert_custody(connection, evidence_id, action, actor, note, row["sha256"], occurred_at)
        append_audit(
            connection, "evidence", evidence_id, f"evidence.custody_{action}", occurred_at,
            {"note": note[:200]}, actor=actor,
        )
        return connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()


def record_evidence_verification(
    evidence_id: str, observed_sha256: str, verified: bool, occurred_at: str,
) -> sqlite3.Row | None:
    status = "verified" if verified else "tampered"
    with session() as connection:
        row = connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            return None
        connection.execute(
            """UPDATE evidence SET status=?, last_verified_at=?, verify_count=verify_count+1
            WHERE id=?""",
            (status, occurred_at, evidence_id),
        )
        note = (
            "Integrity verified: stored digest matches recorded digest."
            if verified
            else f"INTEGRITY FAILURE: observed {observed_sha256}, expected {row['sha256']}."
        )
        _insert_custody(
            connection, evidence_id,
            "verified" if verified else "verify_failed",
            "local", note, observed_sha256, occurred_at,
        )
        append_audit(
            connection, "evidence", evidence_id,
            "evidence.verified" if verified else "evidence.integrity_failed", occurred_at,
            {"expected": row["sha256"], "observed": observed_sha256},
        )
        return connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()


def mark_evidence_missing(evidence_id: str, occurred_at: str) -> sqlite3.Row | None:
    with session() as connection:
        row = connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            return None
        connection.execute("UPDATE evidence SET status='missing' WHERE id=?", (evidence_id,))
        _insert_custody(
            connection, evidence_id, "verify_failed", "local",
            "Stored object is missing from the evidence store.", row["sha256"], occurred_at,
        )
        append_audit(
            connection, "evidence", evidence_id, "evidence.object_missing", occurred_at,
            {"sha256": row["sha256"]},
        )
        return connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()


def link_evidence_to_case(
    evidence_id: str, case_id: str, occurred_at: str, actor: str = "local",
) -> bool:
    with session() as connection:
        evidence = connection.execute(
            "SELECT * FROM evidence WHERE id=?", (evidence_id,)
        ).fetchone()
        if evidence is None:
            return False
        if connection.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone() is None:
            return False
        connection.execute(
            "UPDATE evidence SET case_id=? WHERE id=?", (case_id, evidence_id)
        )
        details = {"evidence_id": evidence_id, "sha256": evidence["sha256"],
                   "name": evidence["original_name"]}
        _insert_custody(
            connection, evidence_id, "case_linked", actor,
            f"Linked to case {case_id}.", evidence["sha256"], occurred_at,
        )
        connection.execute(
            """INSERT INTO case_timeline (case_id, entry_type, actor, details, occurred_at)
            VALUES (?,'evidence.linked',?,?,?)""",
            (case_id, actor, json.dumps(details, separators=(",", ":")), occurred_at),
        )
        connection.execute("UPDATE cases SET updated_at=? WHERE id=?", (occurred_at, case_id))
        append_audit(
            connection, "evidence", evidence_id, "evidence.case_linked", occurred_at,
            {"case_id": case_id}, actor=actor,
        )
        return True


def row_to_evidence(row: sqlite3.Row) -> dict:
    item = dict(row)
    item.pop("storage_path", None)
    item["object_ref"] = f"objects/{item['sha256'][:2]}/{item['sha256']}"
    return item


def row_to_custody(row: sqlite3.Row) -> dict:
    return dict(row)
