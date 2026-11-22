from __future__ import annotations

import json

from app import integration_settings


def _clear_provider_environment(monkeypatch):
    for names in integration_settings.ENV_NAMES.values():
        for name in names.values():
            monkeypatch.delenv(name, raising=False)


def test_provider_credentials_are_saved_securely_and_never_returned(tmp_path, monkeypatch):
    path = tmp_path / "integration_keys.json"
    monkeypatch.setattr(integration_settings, "SETTINGS_PATH", path)
    monkeypatch.setattr(integration_settings, "VERIFY_PATH", tmp_path / "integration_verification.json")
    _clear_provider_environment(monkeypatch)

    result = integration_settings.save_provider_keys({
        "malwarebazaar": "mb-secret",
        "virustotal": "vt-secret",
        "malwarebytes_client_id": "mwb-client",
        "malwarebytes_client_secret": "mwb-secret",
        "malwarebytes_account_id": "account-123",
    })

    assert result["providers"]["malwarebazaar"]["configured"] is True
    assert result["providers"]["virustotal"]["configured"] is True
    assert result["providers"]["malwarebytes"]["configured"] is True
    assert "mb-secret" not in str(result)
    assert "vt-secret" not in str(result)
    assert "mwb-secret" not in str(result)
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == {
        "malwarebazaar": "mb-secret",
        "virustotal": "vt-secret",
        "malwarebytes_client_id": "mwb-client",
        "malwarebytes_client_secret": "mwb-secret",
        "malwarebytes_account_id": "account-123",
    }
    assert integration_settings.provider_key("malwarebazaar") == "mb-secret"
    assert integration_settings.provider_key("virustotal") == "vt-secret"


def test_malwarebytes_requires_all_three_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(integration_settings, "SETTINGS_PATH", tmp_path / "keys.json")
    monkeypatch.setattr(integration_settings, "VERIFY_PATH", tmp_path / "verify.json")
    _clear_provider_environment(monkeypatch)
    result = integration_settings.save_provider_keys({
        "malwarebytes_client_id": "client-id",
        "malwarebytes_client_secret": "client-secret",
    })
    state = result["providers"]["malwarebytes"]
    assert state["configured"] is False
    assert state["configuration"] == "incomplete_credentials"
    assert state["verification"]["status"] == "incomplete"


def test_changed_credentials_invalidate_previous_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(integration_settings, "SETTINGS_PATH", tmp_path / "keys.json")
    monkeypatch.setattr(integration_settings, "VERIFY_PATH", tmp_path / "verify.json")
    _clear_provider_environment(monkeypatch)
    integration_settings.save_provider_keys({"malwarebazaar": "first-key"})
    monkeypatch.setattr(integration_settings, "_verify_malwarebazaar", lambda values: {
        "status": "verified", "message": "API accepted key"
    })
    integration_settings.verify_provider("malwarebazaar")
    assert integration_settings.provider_status()["providers"]["malwarebazaar"]["verification"]["status"] == "verified"

    integration_settings.save_provider_keys({"malwarebazaar": "replacement-key"})
    assert integration_settings.provider_status()["providers"]["malwarebazaar"]["verification"]["status"] == "not_verified"


def test_provider_verification_rejects_invalid_and_records_success(tmp_path, monkeypatch):
    monkeypatch.setattr(integration_settings, "SETTINGS_PATH", tmp_path / "keys.json")
    monkeypatch.setattr(integration_settings, "VERIFY_PATH", tmp_path / "verify.json")
    _clear_provider_environment(monkeypatch)
    integration_settings.save_provider_keys({"malwarebazaar": "random-value"})
    monkeypatch.setattr(integration_settings, "_request", lambda *args, **kwargs: (200, {"query_status": "no_api_key"}))
    result = integration_settings.verify_provider("malwarebazaar")
    assert result["providers"]["malwarebazaar"]["verification"]["status"] == "invalid"

    monkeypatch.setattr(integration_settings, "_request", lambda *args, **kwargs: (200, {"query_status": "ok", "data": []}))
    result = integration_settings.verify_provider("malwarebazaar")
    assert result["providers"]["malwarebazaar"]["verification"]["status"] == "verified"


def test_unsupported_provider_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        integration_settings.verify_provider("unknown")
