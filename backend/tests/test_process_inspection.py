from types import SimpleNamespace

from app import process_inspection


class FakeProcess:
    pid = 4242

    def name(self):
        return "fixture-service"

    def ppid(self):
        return 1

    def username(self):
        return "fixture"

    def status(self):
        return "sleeping"

    def memory_info(self):
        return SimpleNamespace(rss=4096)

    def exe(self):
        return "/usr/bin/fixture-service"

    def create_time(self):
        return 1_700_000_000

    def num_threads(self):
        return 2


def test_process_inspection_reports_executable_mapping_as_unconfirmed(monkeypatch):
    monkeypatch.setattr(process_inspection.psutil, "process_iter", lambda: [FakeProcess()])
    monkeypatch.setattr(
        process_inspection.psutil,
        "net_connections",
        lambda kind: [
            SimpleNamespace(
                pid=4242,
                raddr=SimpleNamespace(ip="203.0.113.10", port=443),
            )
        ],
    )
    monkeypatch.setattr(
        process_inspection,
        "_read_executable_maps",
        lambda pid, remaining: (
            [{"address": "1000-2000", "permissions": "r-xp", "path": "[anonymous]"}],
            3,
            False,
        ),
    )

    result = process_inspection.inspect_processes(max_processes=10, max_total_maps=10)

    assert result["summary"]["processes_inspected"] == 1
    assert result["summary"]["mapping_entries_read"] == 3
    assert result["summary"]["indicators"] == 1
    indicator = result["indicators"][0]
    assert indicator["source"] == "linux_process_memory_inspection"
    assert indicator["assessment"] == "suspicious_unconfirmed"
    assert indicator["confidence"] == "low"
    assert result["processes"][0]["remote_endpoints"] == ["203.0.113.10:443"]
    assert "command_line" not in result["processes"][0]
    assert result["scope"]["process_memory_contents_read"] is False


def test_process_inspection_marks_deleted_executable_without_confirming_malware(monkeypatch):
    process = FakeProcess()
    process.exe = lambda: "/tmp/temporary-loader (deleted)"
    monkeypatch.setattr(process_inspection.psutil, "process_iter", lambda: [process])
    monkeypatch.setattr(process_inspection.psutil, "net_connections", lambda kind: [])
    monkeypatch.setattr(process_inspection, "_read_executable_maps", lambda pid, remaining: ([], 0, False))

    result = process_inspection.inspect_processes()

    assert len(result["indicators"]) == 1
    assert result["indicators"][0]["title"] == "Running process executable has been deleted"
    assert result["indicators"][0]["assessment"] == "suspicious_unconfirmed"
    assert result["indicators"][0]["confidence"] == "medium"


def test_process_inspection_respects_process_limit(monkeypatch):
    processes = [FakeProcess(), FakeProcess()]
    processes[1].pid = 4243
    monkeypatch.setattr(process_inspection.psutil, "process_iter", lambda: processes)
    monkeypatch.setattr(process_inspection.psutil, "net_connections", lambda kind: [])
    monkeypatch.setattr(process_inspection, "_read_executable_maps", lambda pid, remaining: ([], 0, False))

    result = process_inspection.inspect_processes(max_processes=1)

    assert result["summary"]["processes_observed"] == 1
    assert result["summary"]["processes_inspected"] == 1
    assert result["summary"]["processes_truncated"] is True
