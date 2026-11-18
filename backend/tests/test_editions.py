from app import editions


def test_defaults_to_normal_when_unset(monkeypatch):
    monkeypatch.delenv("SENTINEL_EDITION", raising=False)
    manifest = editions.edition_manifest()
    assert manifest["edition"] == "normal"
    assert manifest["display_name"] == "SENTINEL Normal"
    assert manifest["license_enforcement"] == "not_implemented"


def test_accepts_advanced_deployment_mode(monkeypatch):
    monkeypatch.setenv("SENTINEL_EDITION", "advanced")
    manifest = editions.edition_manifest()
    assert manifest["edition"] == "advanced"
    advanced = next(item for item in manifest["features"] if item["id"] == "continuous_monitoring")
    assert advanced["included"] is True
    assert advanced["status"] == "planned"


def test_invalid_edition_falls_back_to_normal(monkeypatch):
    monkeypatch.setenv("SENTINEL_EDITION", "enterprise-unlimited")
    assert editions.current_edition() == "normal"


def test_normal_does_not_include_advanced_features(monkeypatch):
    monkeypatch.setenv("SENTINEL_EDITION", "normal")
    manifest = editions.edition_manifest()
    advanced = next(item for item in manifest["features"] if item["id"] == "sandbox_analysis")
    assert advanced["included"] is False
