"""Hash-only threat-intelligence integrations with bounded persistent caching.

MalwareBazaar provides malware indicators. CIRCL hashlookup provides known-file
context only; a match is not a malware verdict. No file content is uploaded or
downloaded by this module.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
CIRCL_URL = "https://hashlookup.circl.lu/lookup/sha256/"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
FEED_CACHE_TTL = 60 * 60
CIRCL_FOUND_CACHE_TTL = 30 * 24 * 60 * 60
CIRCL_MISS_CACHE_TTL = 7 * 24 * 60 * 60
CIRCL_REQUEST_TIMEOUT = 2.5
DEFAULT_CIRCL_MAX_LOOKUPS = 20


def _cache_path() -> Path:
    configured = os.environ.get("SENTINEL_THREAT_INTEL_CACHE", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[1] / "data" / "threat_intel_cache.json"


def _read_cache() -> dict:
    try:
        value = json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"version": 1, "malwarebazaar": None, "circl": {}}
    if not isinstance(value, dict) or value.get("version") != 1:
        return {"version": 1, "malwarebazaar": None, "circl": {}}
    if not isinstance(value.get("circl"), dict):
        value["circl"] = {}
    return value


def _write_cache(cache: dict) -> None:
    path = _cache_path()
    temporary = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps(cache, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def fetch_recent_malware(*, force_refresh: bool = False) -> dict:
    """Fetch or reuse MalwareBazaar's latest 100 additions (one-hour cache)."""
    from .integration_settings import provider_key\n\n    api_key = provider_key("malwarebazaar")
    if not api_key:
        return {
            "provider": "MalwareBazaar", "status": "not_configured", "enabled": False,
            "records_received": 0,
            "note": "Set SENTINEL_MALWAREBAZAAR_API_KEY in the local backend environment to enable live malware hash intelligence.",
        }

    cache = _read_cache()
    cached = cache.get("malwarebazaar")
    now = time.time()
    if (
        not force_refresh and isinstance(cached, dict)
        and isinstance(cached.get("fetched_at"), (int, float))
        and now - cached["fetched_at"] < FEED_CACHE_TTL
        and isinstance(cached.get("feed"), dict)
        and cached["feed"].get("status") == "ok"
    ):
        feed = dict(cached["feed"])
        feed.update({"cached": True, "cache_age_seconds": max(0, int(now - cached["fetched_at"]))})
        return feed

    body = urlencode({"query": "get_recent", "selector": "100"}).encode("ascii")
    request = Request(
        MALWAREBAZAAR_URL, data=body,
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
            return _stale_or_error(cached, "response_too_large")
        payload = json.loads(raw.decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError):
        return _stale_or_error(cached, "request_failed")

    if not isinstance(payload, dict) or payload.get("query_status") not in ("ok", "no_results"):
        status = payload.get("query_status") if isinstance(payload, dict) else None
        return _stale_or_error(cached, str(status or "invalid_response")[:80])

    records = payload.get("data") or []
    if not isinstance(records, list):
        return _stale_or_error(cached, "invalid_response")
    entries = []
    for record in records:
        if not isinstance(record, dict):
            continue
        digest = str(record.get("sha256_hash", "")).lower()
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            continue
        entries.append({
            "sha256": digest,
            "signature": str(record.get("signature") or "")[:160],
            "file_type": str(record.get("file_type") or "")[:80],
            "first_seen": str(record.get("first_seen") or "")[:40],
            "file_name": str(record.get("file_name") or "")[:200],
        })
    fetched_at = time.time()
    feed = {
        "provider": "MalwareBazaar", "status": "ok", "enabled": True,
        "records_received": len(entries), "feed_scope": "latest 100 additions",
        "entries": entries, "cached": False,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(fetched_at)),
        "note": "A feed match is a known-malware hash indicator. No match does not mean a file is safe.",
    }
    cache["malwarebazaar"] = {"fetched_at": fetched_at, "feed": feed}
    _write_cache(cache)
    return feed


def _stale_or_error(cached: object, reason: str) -> dict:
    if isinstance(cached, dict) and isinstance(cached.get("feed"), dict):
        feed = dict(cached["feed"])
        feed.update({
            "status": "stale", "cached": True,
            "cache_age_seconds": max(0, int(time.time() - cached["fetched_at"])) if isinstance(cached.get("fetched_at"), (int, float)) else None,
            "error": reason,
            "note": "Live MalwareBazaar refresh failed; a previously cached feed was used. Its age is reported and the feed may be incomplete.",
        })
        return feed
    return {
        "provider": "MalwareBazaar", "status": "unavailable", "enabled": True,
        "records_received": 0, "error": reason,
        "note": "Live threat intelligence could not be retrieved; local scanning continued without it.",
    }


def match_recent_hashes(file_hashes: dict[str, list[str]], feed: dict) -> list[dict]:
    """Create findings for exact SHA-256 matches in a current or stale recent feed."""
    if feed.get("status") not in {"ok", "stale"}:
        return []
    findings = []
    for entry in feed.get("entries", []):
        digest = entry["sha256"]
        for path in file_hashes.get(digest, []):
            family = entry.get("signature") or "Unclassified malware"
            findings.append({
                "id": f"malwarebazaar-{digest[:12]}",
                "category": "malware", "severity": "critical",
                "title": f"MalwareBazaar match: {family}",
                "description": "Exact SHA-256 match in MalwareBazaar's recent malware feed. Preserve the file and investigate; this is a strong indicator, not an automatic remediation instruction.",
                "path": path, "sha256": digest, "evidence": "exact_sha256_match",
                "confidence": "high", "source": "malwarebazaar", "engine": "MalwareBazaar",
                "malware_family": family, "first_seen": entry.get("first_seen"),
                "file_type": entry.get("file_type"), "feed_scope": feed.get("feed_scope"),
                "feed_status": feed.get("status"), "feed_cached": feed.get("cached", False),
            })
    return findings


def lookup_circl_hashes(
    file_hashes: dict[str, list[str]], *, max_lookups: int | None = None,
) -> dict:
    """Look up a bounded set of SHA-256 hashes for known-file context, with disk cache."""
    if max_lookups is None:
        try:
            max_lookups = int(os.environ.get("SENTINEL_CIRCL_MAX_LOOKUPS", DEFAULT_CIRCL_MAX_LOOKUPS))
        except ValueError:
            max_lookups = DEFAULT_CIRCL_MAX_LOOKUPS
    max_lookups = max(0, min(max_lookups, 100))
    if max_lookups == 0:
        return {
            "provider": "CIRCL hashlookup", "status": "disabled",
            "lookups_performed": 0, "cache_hits": 0, "matches": [],
            "note": "CIRCL lookups are disabled by SENTINEL_CIRCL_MAX_LOOKUPS=0.",
        }

    cache = _read_cache()
    circl_cache = cache["circl"]
    now = time.time()
    # Prefer hashes shared by multiple paths, then keep ordering deterministic.
    digests = sorted(
        (digest for digest in file_hashes if re.fullmatch(r"[a-f0-9]{64}", digest)),
        key=lambda digest: (-len(file_hashes[digest]), digest),
    )
    selected = digests[:max_lookups]
    matches = []
    cache_hits = 0
    requests_made = 0
    misses = 0
    errors = 0

    for digest in selected:
        cached = circl_cache.get(digest)
        ttl = CIRCL_FOUND_CACHE_TTL if isinstance(cached, dict) and cached.get("status") == "found" else CIRCL_MISS_CACHE_TTL
        was_cached = False
        if (
            isinstance(cached, dict) and isinstance(cached.get("checked_at"), (int, float))
            and now - cached["checked_at"] < ttl
            and cached.get("status") in {"found", "not_found"}
        ):
            result = cached
            cache_hits += 1
            was_cached = True
        else:
            request = Request(
                CIRCL_URL + digest,
                headers={"Accept": "application/json", "User-Agent": "SENTINEL-local-host-assessment/1.0"},
            )
            requests_made += 1
            try:
                with urlopen(request, timeout=CIRCL_REQUEST_TIMEOUT) as response:
                    raw = response.read(64 * 1024 + 1)
                if len(raw) > 64 * 1024:
                    errors += 1
                    break
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    errors += 1
                    break
                product = payload.get("ProductCode")
                result = {
                    "status": "found", "checked_at": now,
                    "file_name": str(payload.get("FileName") or "")[:300],
                    "file_size": str(payload.get("FileSize") or "")[:40],
                    "source": str(payload.get("source") or "")[:200],
                    "database": str(payload.get("db") or "")[:100],
                    "mimetype": str(payload.get("mimetype") or "")[:120],
                    "trust": payload.get("hashlookup:trust"),
                    "product_name": str(product.get("ProductName") or "")[:160] if isinstance(product, dict) else "",
                    "product_version": str(product.get("ProductVersion") or "")[:80] if isinstance(product, dict) else "",
                }
                circl_cache[digest] = result
            except HTTPError as exc:
                if exc.code == 404:
                    result = {"status": "not_found", "checked_at": now}
                    circl_cache[digest] = result
                else:
                    errors += 1
                    break
            except (URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError):
                errors += 1
                break

        if result.get("status") == "found":
            matches.append({
                "sha256": digest, "paths": file_hashes.get(digest, []),
                "file_name": result.get("file_name"), "file_size": result.get("file_size"),
                "source": result.get("source"), "database": result.get("database"),
                "mimetype": result.get("mimetype"), "trust": result.get("trust"),
                "product_name": result.get("product_name"),
                "product_version": result.get("product_version"),
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(result["checked_at"])),
                "cached": was_cached,
            })
        else:
            misses += 1

    if len(circl_cache) > 10000:
        retained = sorted(
            circl_cache.items(),
            key=lambda item: item[1].get("checked_at", 0) if isinstance(item[1], dict) else 0,
            reverse=True,
        )[:10000]
        cache["circl"] = dict(retained)
    _write_cache(cache)
    status = "unavailable" if errors and not (matches or misses) else ("partial" if errors else "ok")
    return {
        "provider": "CIRCL hashlookup", "status": status,
        "hashes_considered": len(selected), "lookups_performed": requests_made,
        "cache_hits": cache_hits, "known_file_matches": len(matches),
        "not_found": misses, "errors": errors,
        "skipped_by_limit": max(0, len(digests) - len(selected)),
        "skipped_after_provider_error": max(0, len(selected) - len(matches) - misses),
        "matches": matches,
        "note": "CIRCL hashlookup supplies known-file context, not a malware verdict. A match does not prove a file is safe or malicious. Only SHA-256 hashes were sent; file contents and paths were not transmitted.",
    }
