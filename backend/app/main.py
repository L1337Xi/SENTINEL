"""SENTINEL local API entry point."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .config import CORS_ORIGINS, MAX_PAGE_SIZE
from .database import initialize_database, row_to_event, session
from .schemas import EventCreate, EventPage

app = FastAPI(
    title="L1337XI SENTINEL API",
    version="0.1.0",
    description="Local-first security event intake and investigation API.",
    docs_url="/docs",
    redoc_url=None,
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
        event_id,
        payload.source,
        payload.event_type,
        payload.severity,
        payload.message,
        payload.host,
        payload.occurred_at.isoformat(),
        json.dumps(payload.metadata, separators=(",", ":"), ensure_ascii=False),
        ingested_at,
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
        total = connection.execute(
            f"SELECT COUNT(*) FROM events{where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM events{where} ORDER BY occurred_at DESC, ingested_at DESC LIMIT ? OFFSET ?",
            [*parameters, limit, offset],
        ).fetchall()
    return {
        "items": [row_to_event(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


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
