"""Local-only storage for optional threat-intelligence provider credentials.

Secrets are never returned by the API. The file is restricted to the service
account (0600) and replaced atomically. This is filesystem permission protection,
not encryption at rest; protect the host and backups accordingly.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .config import ROOT_DIR

SETTINGS_PATH = Path(os.getenv(
    "SENTINEL_INTEGRATION_SETTINGS",
    str(ROOT_DIR / "backend" / "data" / "integration_keys.json"),
))
PROVIDERS = ("malwarebazaar", "virustotal", "malwarebytes")
ENV_NAMES = {
    "malwarebazaar": "SENTINEL_MALWAREBAZAAR_API_KEY",
    "virustotal": "SENTINEL_VIRUSTOTAL_API_KEY",
    "malwarebytes": "SENTINEL_MALWAREBYTES_API_KEY",
}


def _read() -> dict[str, str]:
    try:
        raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raw = {}
    except (OSError, json.JSONDecodeError):
        raw = {}
    if not isinstance(raw, dict):
        return {}
    return {key: value for key, value in raw.items()
            if key in PROVIDERS and isinstance(value, str)}


def provider_status() -> dict:
    saved = _read()
    return {
        "providers": {
            provider: {
                "configured": bool(os.environ.get(ENV_NAMES[provider], "").strip() or saved.get(provider, "").strip()),
                "storage": "environment" if os.environ.get(ENV_NAMES[provider], "").strip() else ("local_file" if saved.get(provider, "").strip() else "none"),
            }
            for provider in PROVIDERS
        },
        "storage_note": "Saved credentials are stored locally with owner-only file permissions (0600). They are not encrypted at rest and are never returned by this API.",
    }


def save_provider_keys(values: dict[str, str | None]) -> dict:
    saved = _read()
    for provider, value in values.items():
        if provider not in PROVIDERS:
            raise ValueError(f"Unsupported provider: {provider}")
        if value is None:
            continue
        secret = value.strip()
        if len(secret) > 512:
            raise ValueError(f"{provider} API key is too long")
        if secret:
            saved[provider] = secret
        else:
            saved.pop(provider, None)

    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".integration-keys-", dir=SETTINGS_PATH.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(saved, handle)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, SETTINGS_PATH)
        os.chmod(SETTINGS_PATH, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return provider_status()

def provider_key(provider: str) -> str:
    """Read one configured provider key for backend integrations only."""
    if provider not in PROVIDERS:
        return ""
    environment_value = os.environ.get(ENV_NAMES[provider], "").strip()
    return environment_value or _read().get(provider, "").strip()
