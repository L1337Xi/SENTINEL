"""Optional MalwareBazaar recent-feed lookup.

Only metadata and SHA-256 hashes are retrieved. SENTINEL never downloads or uploads
samples. The API key is read from the local process environment.
"""
from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API_URL = "https://mb-api.abuse.ch/api/v1/"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024


def fetch_recent_malware() -> dict:
    """Fetch MalwareBazaar's latest 100 additions; return safe status on all failures."""
    api_key = os.environ.get("SENTINEL_MALWAREBAZAAR_API_KEY", "").strip()
    if not api_key:
        return {
            "provider": "MalwareBazaar",
            "status": "not_configured",
            "enabled": False,
            "records_received": 0,
            "note": "Set SENTINEL_MALWAREBAZAAR_API_KEY in the local backend environment to enable live hash intelligence.",
        }

    body = urlencode({"query": "get_recent", "selector": "100"}).encode("ascii")
    request = Request(
        API_URL,
        data=body,
        headers={
            "Auth-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "SENTINEL-local-host-assessment/1.0",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=12) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            return _error("response_too_large")
        payload = json.loads(raw.decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError):
        return _error("request_failed")

    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        status = payload.get("query_status") if isinstance(payload, dict) else None
        return _error(str(status or "invalid_response")[:80])

    records = payload.get("data", [])
    if not isinstance(records, list):
        return _error("invalid_response")
    entries = []
    for record in records:
        if not isinstance(record, dict):
            continue
        digest = str(record.get("sha256_hash", "")).lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            continue
        entries.append({
            "sha256": digest,
            "signature": str(record.get("signature") or "")[:160],
            "file_type": str(record.get("file_type") or "")[:80],
            "first_seen": str(record.get("first_seen") or "")[:40],
            "file_name": str(record.get("file_name") or "")[:200],
        })
    return {
        "provider": "MalwareBazaar",
        "status": "ok",
        "enabled": True,
        "records_received": len(entries),
        "feed_scope": "latest 100 additions",
        "entries": entries,
        "note": "A feed match is a known-malware hash indicator. No match does not mean a file is safe.",
    }


def _error(reason: str) -> dict:
    return {
        "provider": "MalwareBazaar",
        "status": "unavailable",
        "enabled": True,
        "records_received": 0,
        "error": reason,
        "note": "Live threat intelligence could not be retrieved; local scanning continued without it.",
    }


def match_recent_hashes(file_hashes: dict[str, list[str]], feed: dict) -> list[dict]:
    """Create findings for exact SHA-256 matches in the retrieved recent feed."""
    if feed.get("status") != "ok":
        return []
    findings = []
    for entry in feed.get("entries", []):
        digest = entry["sha256"]
        for path in file_hashes.get(digest, []):
            family = entry.get("signature") or "Unclassified malware"
            findings.append({
                "id": f"malwarebazaar-{digest[:12]}",
                "category": "malware",
                "severity": "critical",
                "title": f"MalwareBazaar match: {family}",
                "description": "Exact SHA-256 match in MalwareBazaar's recent malware feed. Preserve the file and investigate; this is a strong indicator, not an automatic remediation instruction.",
                "path": path,
                "sha256": digest,
                "evidence": "exact_sha256_match",
                "confidence": "high",
                "source": "malwarebazaar",
                "engine": "MalwareBazaar",
                "malware_family": family,
                "first_seen": entry.get("first_seen"),
                "file_type": entry.get("file_type"),
                "feed_scope": feed.get("feed_scope"),
            })
    return findings
