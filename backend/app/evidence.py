"""Evidence intake, integrity verification, and chain-of-custody tracking.

Acquired files are hashed while streaming, stored as immutable read-only blobs in a
content-addressed store (never executed, never rewritten), and every action is written
to both the custody ledger and the audit log.
"""
from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile

from . import config
from .database import (
    add_custody_entry,
    create_evidence,
    find_evidence_by_sha,
    get_case,
    get_evidence,
    link_evidence_to_case,
    list_evidence,
    list_evidence_custody,
    mark_evidence_missing,
    record_evidence_verification,
    row_to_custody,
    row_to_evidence,
)
from .schemas import EvidenceCaseLink, EvidenceCustodyCreate

router = APIRouter(prefix="/api/evidence", tags=["evidence"])
CHUNK_SIZE = 1024 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat()


def safe_filename(name: str | None) -> str:
    """Reduce an uploaded name to a harmless label (never used as a storage path)."""
    candidate = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    candidate = "".join(char for char in candidate if char.isprintable()).strip()
    if candidate in {"", ".", ".."}:
        return "unnamed-evidence"
    return candidate[:120]


def _evidence_root() -> Path:
    root = Path(config.EVIDENCE_DIR)
    for subdirectory in ("objects", "incoming"):
        (root / subdirectory).mkdir(parents=True, exist_ok=True)
        os.chmod(root / subdirectory, 0o700)
    return root


def _store_upload(upload: UploadFile) -> tuple[Path, str, int]:
    """Stream the upload to a temporary file, hashing it, then move it into the store."""
    root = _evidence_root()
    temp_path = root / "incoming" / f"{uuid4().hex}.part"
    digest = hashlib.sha256()
    size = 0
    try:
        with temp_path.open("xb") as handle:
            while chunk := upload.file.read(CHUNK_SIZE):
                size += len(chunk)
                if size > config.MAX_EVIDENCE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Evidence exceeds the {config.MAX_EVIDENCE_BYTES} byte limit.",
                    )
                digest.update(chunk)
                handle.write(chunk)
        if size == 0:
            raise HTTPException(status_code=422, detail="Evidence file is empty.")
        sha256 = digest.hexdigest()
        destination = root / "objects" / sha256[:2] / sha256
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(destination.parent, 0o700)
        if destination.exists():
            temp_path.unlink(missing_ok=True)
        else:
            os.replace(temp_path, destination)
        os.chmod(destination, 0o400)
        return destination, sha256, size
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
    finally:
        upload.file.close()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized(evidence_id: str) -> str:
    try:
        return str(UUID(evidence_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Evidence not found.") from exc


@router.post("", status_code=201)
def acquire_evidence(
    file: Annotated[UploadFile, File()],
    case_id: Annotated[str | None, Form()] = None,
    source: Annotated[str, Form(max_length=80)] = "local-upload",
    note: Annotated[str, Form(max_length=2000)] = "",
) -> dict:
    normalized_case: str | None = None
    if case_id:
        try:
            normalized_case = str(UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Case not found.") from exc
        if get_case(normalized_case) is None:
            raise HTTPException(status_code=404, detail="Case not found.")

    stored_path, sha256, size = _store_upload(file)
    existing = find_evidence_by_sha(sha256)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "This exact file has already been acquired.",
                "existing_evidence_id": existing["id"],
                "sha256": sha256,
            },
        )

    acquired_at = _now()
    row = create_evidence(
        str(uuid4()),
        safe_filename(file.filename),
        size,
        sha256,
        (file.content_type or None),
        source.strip() or "local-upload",
        str(stored_path),
        acquired_at,
        case_id=normalized_case,
        note=note.strip(),
    )
    return row_to_evidence(row)


@router.get("")
def list_acquired_evidence(
    case_id: str | None = Query(default=None),
    sha256: str | None = Query(default=None, pattern="^[a-f0-9]{64}$"),
    status: str | None = Query(
        default=None, pattern="^(acquired|verified|tampered|missing|released)$"
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    normalized_case = _normalized(case_id) if case_id else None
    rows, total = list_evidence(normalized_case, sha256, status, limit, offset)
    return {
        "items": [row_to_evidence(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{evidence_id}")
def evidence_detail(evidence_id: str) -> dict:
    normalized = _normalized(evidence_id)
    row = get_evidence(normalized)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    custody = list_evidence_custody(normalized)
    return {
        **row_to_evidence(row),
        "custody": [row_to_custody(entry) for entry in custody],
    }


@router.post("/{evidence_id}/verify")
def verify_evidence(evidence_id: str) -> dict:
    normalized = _normalized(evidence_id)
    row = get_evidence(normalized)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    stored_path = Path(row["storage_path"])
    checked_at = _now()
    if not stored_path.is_file():
        updated = mark_evidence_missing(normalized, checked_at)
        return {
            "evidence_id": normalized,
            "verified": False,
            "status": updated["status"] if updated else "missing",
            "expected_sha256": row["sha256"],
            "observed_sha256": None,
            "checked_at": checked_at,
        }
    observed = _digest_file(stored_path)
    verified = observed == row["sha256"]
    updated = record_evidence_verification(normalized, observed, verified, checked_at)
    return {
        "evidence_id": normalized,
        "verified": verified,
        "status": updated["status"] if updated else ("verified" if verified else "tampered"),
        "expected_sha256": row["sha256"],
        "observed_sha256": observed,
        "checked_at": checked_at,
    }


@router.post("/{evidence_id}/custody", status_code=201)
def record_custody_action(evidence_id: str, payload: EvidenceCustodyCreate) -> dict:
    normalized = _normalized(evidence_id)
    row = add_custody_entry(
        normalized, payload.action, payload.actor, payload.note, _now()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    custody = list_evidence_custody(normalized, limit=1)
    return {
        "evidence": row_to_evidence(row),
        "custody_entry": row_to_custody(custody[0]),
    }


@router.post("/{evidence_id}/case", status_code=201)
def attach_evidence_to_case(evidence_id: str, payload: EvidenceCaseLink) -> dict:
    normalized = _normalized(evidence_id)
    case_id = str(payload.case_id)
    if not link_evidence_to_case(normalized, case_id, _now()):
        raise HTTPException(status_code=404, detail="Evidence or case not found.")
    return {"evidence_id": normalized, "case_id": case_id, "linked": True}
