"""SENTINEL local API entry point."""
from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4
import json

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .config import CORS_ORIGINS, MAX_PAGE_SIZE
from .database import create_scan, initialize_database, row_to_event, row_to_scan, session, update_scan
from .scanner import network_discovery, system_inventory, validate_local_network
from .schemas import EventCreate, EventPage, NetworkScanCreate

app = FastAPI(
    title="L1337XI SENTINEL API",
    version="0.2.0",
    description="Local-first security event intake, host inventory, and scoped network discovery.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.on_event("startup")
def on_startup() -> None:
    initialize_database()


@app.get("/api/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-api", "version": app.version}


@app.post("/api/events", status_code=201, tags=["events"])
def create_event(payload: EventCreate) -> dict:
    event_id = str(uuid4())
    ingested_at = datetime.now(UTC).isoformat()
    values = (
        event_id, payload.source, payload.event_type, payload.severity,
        payload.message, payload.host, payload.occurred_at.isoformat(),
        json.dumps(payload.metadata, separators=(",", ":"), ensure_ascii=False), ingested_at,
    )
    with session() as connection:
        connection.execute(
            """INSERT INTO events
            (id, source, event_type, severity, message, host, occurred_at, metadata, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
        )
        row = connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return row_to_event(row)


@app.get("/api/events", response_model=EventPage, tags=["events"])
def list_events(
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> dict:
    clauses: list[str] = []
    parameters: list[object] = []
    if severity:
        clauses.append("severity = ?")
        parameters.append(severity)
    if search:
        clauses.append("(message LIKE ? OR source LIKE ? OR event_type LIKE ? OR host LIKE ?)")
        term = f"%{search}%"
        parameters.extend([term, term, term, term])
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with session() as connection:
        total = connection.execute(f"SELECT COUNT(*) FROM events{where}", parameters).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM events{where} ORDER BY occurred_at DESC, ingested_at DESC LIMIT ? OFFSET ?",
            [*parameters, limit, offset],
        ).fetchall()
    return {"items": [row_to_event(row) for row in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/events/{event_id}", tags=["events"])
def get_event(event_id: str) -> dict:
    try:
        from uuid import UUID
        normalized_id = str(UUID(event_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Event not found.") from exc
    with session() as connection:
        row = connection.execute("SELECT * FROM events WHERE id = ?", (normalized_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found.")
    return row_to_event(row)


def _execute_scan(scan_id: str, scan_type: str, target: str) -> None:
    update_scan(scan_id, status="running")
    try:
        result = system_inventory() if scan_type == "system" else network_discovery(target)
        update_scan(scan_id, status="completed", result=result, completed_at=datetime.now(UTC).isoformat())
    except Exception as exc:
        update_scan(scan_id, status="failed", error=str(exc)[:500], completed_at=datetime.now(UTC).isoformat())


@app.get("/api/scans", tags=["scans"])
def list_scans(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    with session() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"items": [row_to_scan(row) for row in rows]}


@app.get("/api/scans/{scan_id}", tags=["scans"])
def get_scan(scan_id: str) -> dict:
    with session() as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return row_to_scan(row)


@app.post("/api/scans/system", status_code=202, tags=["scans"])
def start_system_scan(background_tasks: BackgroundTasks) -> dict:
    scan_id = str(uuid4())
    started_at = datetime.now(UTC).isoformat()
    create_scan(scan_id, "system", "This machine", started_at)
    background_tasks.add_task(_execute_scan, scan_id, "system", "This machine")
    return {"id": scan_id, "scan_type": "system", "status": "queued", "target": "This machine"}


@app.post("/api/scans/network", status_code=202, tags=["scans"])
def start_network_scan(payload: NetworkScanCreate, background_tasks: BackgroundTasks) -> dict:
    try:
        network = validate_local_network(payload.network)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan_id = str(uuid4())
    started_at = datetime.now(UTC).isoformat()
    target = str(network)
    create_scan(scan_id, "network", target, started_at)
    background_tasks.add_task(_execute_scan, scan_id, "network", target)
    return {"id": scan_id, "scan_type": "network", "status": "queued", "target": target}


@app.get("/api/scanner/networks", tags=["scans"])
def available_networks() -> dict:
    from .scanner import local_networks
    return {"items": local_networks()}
