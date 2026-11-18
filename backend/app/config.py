"""Runtime configuration for the local SENTINEL API."""
from __future__ import annotations

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
DATABASE_PATH = Path(os.getenv("SENTINEL_DATABASE_PATH", str(ROOT_DIR / "backend" / "data" / "sentinel.db")))
EVIDENCE_DIR = Path(os.getenv("SENTINEL_EVIDENCE_DIR", str(ROOT_DIR / "storage" / "evidence")))
MAX_EVIDENCE_BYTES = max(1, int(os.getenv("SENTINEL_MAX_EVIDENCE_BYTES", str(512 * 1024 * 1024))))
MAX_PAGE_SIZE = max(1, min(int(os.getenv("SENTINEL_MAX_PAGE_SIZE", "100")), 500))
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "SENTINEL_CORS_ORIGINS",
        "http://127.0.0.1:5176,http://localhost:5176",
    ).split(",")
    if origin.strip()
]
