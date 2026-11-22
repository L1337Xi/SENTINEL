from __future__ import annotations

import json

from app import integration_settings


def test_provider_keys_are_saved_with_restricted_permissions_and_never_returned(
    tmp_path, monkeypatch
):
    path = tmp_path / "integration_keys.json"
    monkeypatch.setattr(integration_settings, "SETTINGS_PATH", path)
    for name in integration_settings.ENV_NAMES.values():
        monkeypatch.delenv(name, raising=False)

    result = integration_settings.save_provider_keys(
        {"malwarebazaar": "mb-secret", "virustotal": "vt-secret"}
    )

    assert result["providers"]["malwarebazaar"]["configured"] is True
    assert result["providers"]["virustotal"]["configured"] is True
    assert result["providers"]["malwarebytes"]["configured"] is False
    assert "mb-secret" not in str(result)
    assert "vt-secret" not in str(result)
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == {
        "malwarebazaar": "mb-secret",
        "virustotal": "vt-secret",
    }
    assert integration_settings.provider_key("malwarebazaar") == "mb-secret"


def test_empty_value_clears_saved_key_and_environment_takes_precedence(
    tmp_path, monkeypatch
):
    path = tmp_path / "integration_keys.json"
    monkeypatch.setattr(integration_settings, "SETTINGS_PATH", path)
    monkeypatch.delenv("SENTINEL_MALWAREBAZAAR_API_KEY", raising=False)
    integration_settings.save_provider_keys({"malwarebazaar": "saved-secret"})

    monkeypatch.setenv("SENTINEL_MALWAREBAZAAR_API_KEY", "environment-secret")
    assert integration_settings.provider_key("malwarebazaar") == "environment-secret"
    integration_settings.save_provider_keys({"malwarebazaar": ""})
    assert integration_settings.provider_key("malwarebazaar") == "environment-secret"
    monkeypatch.delenv("SENTINEL_MALWAREBAZAAR_API_KEY")
    assert integration_settings.provider_key("malwarebazaar") == ""
    assert integration_settings.provider_status()["providers"]["malwarebazaar"]["configured"] is False
