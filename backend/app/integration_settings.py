"""Secure local storage and live verification for threat-intelligence providers.

Provider credentials are never returned by the API. Verification performs a small,
read-only authenticated request against each provider's official API.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import ROOT_DIR

SETTINGS_PATH = Path(os.getenv(
    "SENTINEL_INTEGRATION_SETTINGS",
    str(ROOT_DIR / "backend" / "data" / "integration_keys.json"),
))
VERIFY_PATH = SETTINGS_PATH.with_name("integration_verification.json")
PROVIDERS = ("malwarebazaar", "virustotal", "malwarebytes")
KEY_FIELDS = {
    "malwarebazaar": ("malwarebazaar",),
    "virustotal": ("virustotal",),
    "malwarebytes": (
        "malwarebytes_client_id", "malwarebytes_client_secret",
        "malwarebytes_account_id",
    ),
}
ENV_NAMES = {
    "malwarebazaar": {"malwarebazaar": "SENTINEL_MALWAREBAZAAR_API_KEY"},
    "virustotal": {"virustotal": "SENTINEL_VIRUSTOTAL_API_KEY"},
    "malwarebytes": {
        "malwarebytes_client_id": "SENTINEL_MALWAREBYTES_CLIENT_ID",
        "malwarebytes_client_secret": "SENTINEL_MALWAREBYTES_CLIENT_SECRET",
        "malwarebytes_account_id": "SENTINEL_MALWAREBYTES_ACCOUNT_ID",
    },
}
MAX_RESPONSE_BYTES = 256 * 1024
REQUEST_TIMEOUT = 12
VT_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _read(path: Path, allowed: set[str]) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {key: value for key, value in raw.items()
            if key in allowed and isinstance(value, str)}


def _write(path: Path, values: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".integration-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(values, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _credentials() -> tuple[dict[str, str], dict[str, str]]:
    saved = _read(SETTINGS_PATH, {field for fields in KEY_FIELDS.values() for field in fields})
    values: dict[str, str] = {}
    sources: dict[str, str] = {}
    for provider, fields in KEY_FIELDS.items():
        for field in fields:
            env_name = ENV_NAMES[provider][field]
            env_value = os.environ.get(env_name, "").strip()
            value = env_value or saved.get(field, "").strip()
            if value:
                values[field] = value
                sources[field] = "environment" if env_value else "local_file"
    return values, sources


def provider_key(provider: str) -> str:
    """Return the configured single-key credential for backend integrations."""
    if provider not in ("malwarebazaar", "virustotal"):
        return ""
    values, _ = _credentials()
    return values.get(provider, "")


def _provider_config(provider: str, values: dict[str, str]) -> tuple[bool, str]:
    if provider in ("malwarebazaar", "virustotal"):
        return bool(values.get(provider)), "configured" if values.get(provider) else "missing"
    required = KEY_FIELDS["malwarebytes"]
    present = [bool(values.get(field)) for field in required]
    if all(present):
        return True, "configured"
    if any(present):
        return False, "incomplete_credentials"
    return False, "missing"


def _verification_state() -> dict:
    try:
        raw = json.loads(VERIFY_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {key: value for key, value in raw.items()
            if key in PROVIDERS and isinstance(value, dict)}


def _legacy_malwarebytes_key_present() -> bool:
    """Detect the obsolete single-field key saved by earlier SENTINEL versions."""
    try:
        raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return False
    return isinstance(raw, dict) and isinstance(raw.get("malwarebytes"), str) and bool(raw["malwarebytes"].strip())


def provider_status() -> dict:
    values, sources = _credentials()
    verification = _verification_state()
    result = {}
    for provider in PROVIDERS:
        configured, config_state = _provider_config(provider, values)
        if provider == "malwarebytes" and not configured and _legacy_malwarebytes_key_present():
            config_state = "legacy_single_key"
        state = verification.get(provider, {})
        if not isinstance(state, dict):
            state = {}
        result[provider] = {
            "configured": configured,
            "configuration": config_state,
            "storage": (
                "environment" if any(sources.get(field) == "environment" for field in KEY_FIELDS[provider])
                else "local_file" if configured else "none"
            ),
            "verification": state if configured else {
                "status": "legacy_key_unsupported" if config_state == "legacy_single_key" else ("incomplete" if config_state == "incomplete_credentials" else "not_configured"),
                "message": (
                    "An old single-key Malwarebytes value was found. Nebula requires Client ID, Client Secret and Account ID; clear the old value and enter the three correct credentials."
                    if config_state == "legacy_single_key" else (
                        "Malwarebytes requires Client ID, Client Secret and Account ID."
                        if config_state == "incomplete_credentials" else "Credentials are not configured."
                    )
                ),
            },
        }
    return {
        "providers": result,
        "storage_note": "Credentials are stored locally with owner-only file permissions (0600). They are not encrypted at rest and are never returned by this API.",
    }


def save_provider_keys(values: dict[str, str | None]) -> dict:
    allowed = {field for fields in KEY_FIELDS.values() for field in fields}
    saved = _read(SETTINGS_PATH, allowed)
    changed_providers: set[str] = set()
    for field, value in values.items():
        if field not in allowed:
            raise ValueError(f"Unsupported credential field: {field}")
        if value is None:
            continue
        secret = value.strip()
        if len(secret) > 512:
            raise ValueError(f"{field} is too long")
        if secret:
            saved[field] = secret
        else:
            saved.pop(field, None)
        for provider, fields in KEY_FIELDS.items():
            if field in fields:
                changed_providers.add(provider)
    _write(SETTINGS_PATH, saved)
    states = _verification_state()
    for provider in changed_providers:
        states[provider] = {
            "status": "not_verified",
            "message": "Credentials changed. Verify them against the provider API.",
            "checked_at": datetime.now(UTC).isoformat(),
        }
    _write(VERIFY_PATH, states)
    return provider_status()


def _request(url: str, *, method: str = "GET", headers: dict | None = None, body: bytes | None = None) -> tuple[int, dict]:
    request = Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as exc:
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
        status = exc.code
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Provider could not be reached. Check network connectivity and try again.") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("Provider returned an unexpectedly large response.")
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeError, json.JSONDecodeError):
        payload = {}
    return status, payload if isinstance(payload, dict) else {}


def _verify_malwarebazaar(values: dict[str, str]) -> dict:
    key = values.get("malwarebazaar", "")
    if not key:
        return {"status": "not_configured", "message": "Enter a MalwareBazaar Auth-Key first."}
    body = urlencode({"query": "get_recent", "selector": "100"}).encode("ascii")
    status, payload = _request(
        "https://mb-api.abuse.ch/api/v1/", method="POST", body=body,
        headers={"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json", "User-Agent": "SENTINEL/0.3"},
    )
    query_status = str(payload.get("query_status", ""))
    if status == 200 and query_status in {"ok", "no_results"}:
        return {"status": "verified", "message": "MalwareBazaar authenticated successfully; recent-feed API responded.",
                "records_received": len(payload.get("data") or []), "http_status": status}
    if query_status == "user_blacklisted":
        return {"status": "rejected", "message": "MalwareBazaar reports this Auth-Key is blacklisted.", "http_status": status}
    if status in (401, 403) or query_status in {"no_api_key", "invalid_api_key"}:
        return {"status": "invalid", "message": "MalwareBazaar rejected this Auth-Key.", "http_status": status}
    return {"status": "error", "message": "MalwareBazaar did not return the expected authenticated feed response.",
            "http_status": status, "provider_code": query_status[:80]}


def _verify_virustotal(values: dict[str, str]) -> dict:
    key = values.get("virustotal", "")
    if not key:
        return {"status": "not_configured", "message": "Enter a VirusTotal API key first."}
    status, payload = _request(
        f"https://www.virustotal.com/api/v3/files/{VT_EMPTY_SHA256}",
        headers={"x-apikey": key, "Accept": "application/json", "User-Agent": "SENTINEL/0.3"},
    )
    if status == 200 and isinstance(payload.get("data"), dict):
        return {"status": "verified", "message": "VirusTotal authenticated successfully; file-report API responded.",
                "http_status": status}
    error = payload.get("error", {})
    code = str(error.get("code", "")) if isinstance(error, dict) else ""
    if status == 404 and code in {"NotFoundError", "NotFound"}:
        return {"status": "verified", "message": "VirusTotal accepted the API key. The harmless test hash has no report.",
                "http_status": status}
    if status == 401:
        return {"status": "invalid", "message": "VirusTotal rejected this API key.", "http_status": status}
    if status == 403:
        return {"status": "access_denied", "message": "VirusTotal recognised the request but denied this endpoint or account tier. Check API permissions and licence.", "http_status": status}
    if status == 429:
        return {"status": "rate_limited", "message": "VirusTotal rate limit reached. Retry later; the key has not been verified.", "http_status": status}
    return {"status": "error", "message": "VirusTotal verification did not receive the expected file-report response.",
            "http_status": status, "provider_code": code[:80]}


def _verify_malwarebytes(values: dict[str, str]) -> dict:
    client_id = values.get("malwarebytes_client_id", "")
    client_secret = values.get("malwarebytes_client_secret", "")
    account_id = values.get("malwarebytes_account_id", "")
    if not all((client_id, client_secret, account_id)):
        return {"status": "incomplete", "message": "Malwarebytes requires Client ID, Client Secret and Account ID."}
    encoded = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
    body = urlencode({"grant_type": "client_credentials", "scope": "read"}).encode("ascii")
    status, payload = _request(
        "https://api.malwarebytes.com/oauth2/token", method="POST", body=body,
        headers={"Authorization": f"Basic {encoded}", "Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json", "User-Agent": "SENTINEL/0.3"},
    )
    token = payload.get("access_token")
    if status != 200 or not isinstance(token, str) or not token:
        if status in (400, 401, 403):
            return {"status": "invalid", "message": "Malwarebytes rejected the Client ID/Client Secret or the requested read scope.", "http_status": status}
        return {"status": "error", "message": "Malwarebytes OAuth token request failed.", "http_status": status}
    account_status, account_payload = _request(
        "https://api.malwarebytes.com/nebula/v1/account",
        headers={"Authorization": f"Bearer {token}", "accountid": account_id,
                 "Accept": "application/json", "User-Agent": "SENTINEL/0.3"},
    )
    if account_status == 200 and isinstance(account_payload, dict):
        return {"status": "verified", "message": "Malwarebytes OAuth authentication and Nebula account access both succeeded.",
                "http_status": account_status}
    if account_status in (401, 403, 404):
        return {"status": "account_or_scope_error", "message": "Client credentials obtained a token, but Nebula rejected the Account ID or read permission.",
                "http_status": account_status}
    return {"status": "error", "message": "Malwarebytes issued a token, but the account verification request failed.",
            "http_status": account_status}


def verify_provider(provider: str) -> dict:
    """Verify saved provider credentials against the provider's real API."""
    if provider not in PROVIDERS:
        raise ValueError(f"Unsupported provider: {provider}")
    values, _ = _credentials()
    configured, config_state = _provider_config(provider, values)
    if not configured:
        result = {
            "status": "incomplete" if config_state == "incomplete_credentials" else "not_configured",
            "message": (
                "Malwarebytes requires Client ID, Client Secret and Account ID."
                if config_state == "incomplete_credentials" else "Configure the required credentials first."
            ),
        }
    else:
        try:
            verifier = {
                "malwarebazaar": _verify_malwarebazaar,
                "virustotal": _verify_virustotal,
                "malwarebytes": _verify_malwarebytes,
            }[provider]
            result = verifier(values)
        except RuntimeError as exc:
            result = {"status": "unavailable", "message": str(exc)}
    result["checked_at"] = datetime.now(UTC).isoformat()
    states = _verification_state()
    # Do not persist response bodies, tokens, headers, or credential material.
    states[provider] = result
    _write(VERIFY_PATH, states)
    return provider_status()
