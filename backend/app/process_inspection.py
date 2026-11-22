"""Bounded, read-only Linux process and executable-memory inspection.

This module inventories process metadata and executable mappings. It never reads
process memory contents, suspends processes, injects code, or changes host state.
Indicators are investigation leads, not standalone malware verdicts.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import time

import psutil

MAX_PROCESSES = 2000
MAX_MAPS_PER_PROCESS = 256
MAX_TOTAL_MAPS = 10000
MAX_INDICATORS = 500
MAX_REMOTE_ENDPOINTS = 8
MAX_PROCESS_SECONDS = 15
SUSPICIOUS_EXECUTABLE_ROOTS = ("/tmp/", "/var/tmp/", "/dev/shm/")
MAP_LINE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+"
    r"[0-9a-f]+\s+[0-9a-f:]+\s+\d+\s*(.*)$"
)


def _read_executable_maps(pid: int, remaining: int) -> tuple[list[dict[str, str]], int, bool]:
    """Read only the process maps metadata, with strict per-process and global bounds."""
    maps: list[dict[str, str]] = []
    path = Path("/proc") / str(pid) / "maps"
    truncated = False
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for index, line in enumerate(stream):
                if index >= min(MAX_MAPS_PER_PROCESS, remaining):
                    truncated = True
                    break
                match = MAP_LINE.match(line.rstrip("\n"))
                if not match:
                    continue
                permissions = match.group(3)
                if "x" not in permissions:
                    continue
                mapped_path = match.group(4).strip()
                maps.append({
                    "address": f"{match.group(1)}-{match.group(2)}",
                    "permissions": permissions,
                    "path": mapped_path or "[anonymous]",
                })
    except (OSError, PermissionError, ProcessLookupError):
        return [], 0, False
    return maps, index + 1 if "index" in locals() else 0, truncated


def inspect_processes(
    *,
    max_processes: int = MAX_PROCESSES,
    max_total_maps: int = MAX_TOTAL_MAPS,
    max_seconds: float = MAX_PROCESS_SECONDS,
) -> dict[str, Any]:
    """Collect bounded process metadata and executable mapping indicators."""
    started = datetime.now(UTC).isoformat()
    started_monotonic = time.monotonic()
    process_rows: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    map_count = 0
    maps_truncated = False
    inaccessible = 0
    observed = 0
    processes_truncated = False
    time_budget_exceeded = False
    connections_by_pid: dict[int, list[str]] = defaultdict(list)
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        connections = []
    for connection in connections:
        if connection.pid is None:
            continue
        remote = getattr(connection, "raddr", None)
        if remote:
            endpoint = f"{remote.ip}:{remote.port}"
            if endpoint not in connections_by_pid[connection.pid]:
                connections_by_pid[connection.pid].append(endpoint)

    for process in psutil.process_iter():
        if time.monotonic() - started_monotonic >= max_seconds:
            time_budget_exceeded = True
            break
        if observed >= max_processes:
            processes_truncated = True
            break
        observed += 1
        try:
            pid = process.pid
            name = process.name() or "unknown"
            ppid = process.ppid()
            username = process.username()
            status = process.status()
            memory = process.memory_info()
            executable = process.exe()
            create_time = process.create_time()
            thread_count = process.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            inaccessible += 1
            continue

        process_indicators: list[dict[str, str]] = []
        executable_lower = executable.lower()
        if executable_lower.endswith(" (deleted)"):
            process_indicators.append({
                "id": "deleted_executable",
                "title": "Running process executable has been deleted",
                "evidence": executable[:500],
                "confidence": "medium",
            })
        elif executable_lower.startswith("memfd:") or "/memfd:" in executable_lower:
            process_indicators.append({
                "id": "memfd_executable",
                "title": "Process executable is backed by a memfd object",
                "evidence": executable[:500],
                "confidence": "medium",
            })
        elif executable.startswith(SUSPICIOUS_EXECUTABLE_ROOTS):
            process_indicators.append({
                "id": "writable_location_executable",
                "title": "Process executable is running from a temporary or shared-memory path",
                "evidence": executable[:500],
                "confidence": "low",
            })

        remaining = max_total_maps - map_count
        executable_maps: list[dict[str, str]] = []
        if remaining > 0:
            executable_maps, consumed, was_truncated = _read_executable_maps(pid, remaining)
            map_count += consumed
            maps_truncated = maps_truncated or was_truncated
        else:
            maps_truncated = True

        for mapping in executable_maps:
            mapped_path = mapping["path"]
            lowered_path = mapped_path.lower()
            if "memfd:" in lowered_path:
                process_indicators.append({
                    "id": "memfd_executable_mapping",
                    "title": "Executable memory mapping is backed by memfd",
                    "evidence": f'{mapping["address"]} {mapping["permissions"]} {mapped_path}'[:500],
                    "confidence": "medium",
                })
            elif mapped_path == "[anonymous]":
                process_indicators.append({
                    "id": "anonymous_executable_mapping",
                    "title": "Anonymous executable memory mapping observed",
                    "evidence": f'{mapping["address"]} {mapping["permissions"]} [anonymous]'[:500],
                    "confidence": "low",
                })
            if "w" in mapping["permissions"] and "x" in mapping["permissions"]:
                process_indicators.append({
                    "id": "writable_executable_mapping",
                    "title": "Writable and executable memory mapping observed",
                    "evidence": f'{mapping["address"]} {mapping["permissions"]} {mapped_path}'[:500],
                    "confidence": "low",
                })
            elif mapped_path.endswith(" (deleted)"):
                process_indicators.append({
                    "id": "deleted_executable_mapping",
                    "title": "Executable mapping references a deleted file",
                    "evidence": f'{mapping["address"]} {mapping["permissions"]} {mapped_path}'[:500],
                    "confidence": "medium",
                })

        unique_indicators = {
            (item["id"], item["evidence"]): item for item in process_indicators
        }
        process_indicators = list(unique_indicators.values())
        if process_indicators and len(indicators) < MAX_INDICATORS:
            for item in process_indicators:
                if len(indicators) >= MAX_INDICATORS:
                    break
                indicators.append({
                    "id": f'process-{pid}-{item["id"]}-{len(indicators)}',
                    "category": "process_memory",
                    "severity": "medium" if item["confidence"] == "medium" else "low",
                    "title": item["title"],
                    "description": (
                        "This process or mapping characteristic can occur in legitimate software. "
                        "Validate the executable, package ownership, parent process and activity "
                        "before treating it as malicious."
                    ),
                    "evidence": item["evidence"],
                    "confidence": item["confidence"],
                    "assessment": "suspicious_unconfirmed",
                    "source": "linux_process_memory_inspection",
                    "pid": pid,
                    "process_name": name[:200],
                    "executable": executable[:500],
                })

        process_rows.append({
            "pid": pid,
            "name": name[:200],
            "ppid": ppid,
            "user": username,
            "status": status,
            "executable": executable[:500],
            "memory_rss_bytes": int(memory.rss),
            "threads": thread_count,
            "started_at": datetime.fromtimestamp(create_time, UTC).isoformat(),
            "executable_mapping_count": len(executable_maps),
            "indicators": [item["id"] for item in process_indicators],
            "remote_endpoints": connections_by_pid.get(pid, [])[:MAX_REMOTE_ENDPOINTS],
        })

    process_rows.sort(key=lambda item: (item["name"].lower(), item["pid"]))
    parent_names = {item["pid"]: item["name"] for item in process_rows}
    for item in process_rows:
        item["parent_name"] = parent_names.get(item["ppid"], "not visible to SENTINEL")
    counts = Counter(item["id"].split("-")[-2] for item in indicators)
    return {
        "engine": "SENTINEL Linux process and executable-memory inspection",
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "scope": {
            "max_processes": max_processes,
            "max_mapping_entries": max_total_maps,
            "max_maps_per_process": MAX_MAPS_PER_PROCESS,
            "max_seconds": max_seconds,
            "process_command_lines_collected": False,
            "process_memory_contents_read": False,
        },
        "summary": {
            "processes_observed": observed,
            "processes_inspected": len(process_rows),
            "processes_inaccessible": inaccessible,
            "mapping_entries_read": map_count,
            "processes_truncated": processes_truncated,
            "time_budget_exceeded": time_budget_exceeded,
            "mappings_truncated": maps_truncated,
            "indicators": len(indicators),
            "indicator_counts": dict(counts),
        },
        "processes": process_rows,
        "indicators": indicators,
        "limitations": [
            "Only process metadata and executable mapping metadata were inspected; process memory contents were not read or dumped.",
            "Command lines are intentionally excluded because they can contain passwords, tokens and other secrets.",
            "Anonymous executable mappings, memfd objects and deleted executables can be legitimate; indicators require investigation and are not malware verdicts.",
            "Visibility depends on the permissions of the SENTINEL service account and the host kernel.",
            "Process count, mapping count and elapsed time are bounded; a truncated result is not a complete inventory.",
            "Network endpoints are metadata observed from the local socket table; encrypted payloads are not inspected.",
        ],
    }
