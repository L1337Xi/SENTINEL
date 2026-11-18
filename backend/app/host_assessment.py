"""Read-only local host security assessment.

The scanner never executes discovered files, changes host settings, quarantines files,
or sends telemetry off-host. Hash indicators are supplied by the operator in a local
JSON file; no remote threat-intelligence feed is assumed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_EXCLUDES = {
    "/proc", "/sys", "/dev", "/run", "/var/cache", "/var/tmp",
    "/.git", "/node_modules", "/.venv", "/venv", "/__pycache__",
}
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FILES = 50000
MAX_SECONDS = 180
TEXT_SUFFIXES = {".sh", ".bash", ".py", ".pl", ".rb", ".php", ".js", ".ps1", ".service", ".desktop"}
CAPABILITY_PATTERNS = {
    "network_communication": (r"curl\s|wget\s|urllib|requests\.|socket\.|http[s]?://", "Network communication"),
    "persistence": (r"crontab|systemctl\s+enable|\.config/autostart|/etc/cron|authorized_keys", "Persistence modification"),
    "credential_access": (r"/etc/shadow|/etc/passwd|credential|password|keyring|\.ssh/", "Credential or key access"),
    "command_execution": (r"subprocess\.|os\.system|exec\(|popen\(|bash\s+-c|sh\s+-c", "Command execution"),
    "destructive_actions": (r"rm\s+-rf|mkfs\.|shred\s|dd\s+if=|wipefs", "Potential destructive file or disk action"),
    "privilege_escalation": (r"sudo\s|setuid|chmod\s+[47]|/etc/sudoers", "Privilege or permission modification"),
}


def _load_indicators() -> dict[str, dict[str, Any]]:
    configured = os.environ.get("SENTINEL_HASH_DB", "/etc/sentinel/hash_iocs.json")
    path = Path(configured)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    items = raw.get("indicators", raw) if isinstance(raw, dict) else {}
    if not isinstance(items, dict):
        return {}
    return {
        str(digest).lower(): value if isinstance(value, dict) else {"label": str(value)}
        for digest, value in items.items()
        if re.fullmatch(r"[a-fA-F0-9]{64}", str(digest))
    }


def _script_capabilities(path: Path) -> list[dict[str, str]]:
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return []
    try:
        with path.open("rb") as stream:
            sample = stream.read(256 * 1024).decode("utf-8", errors="ignore").lower()
    except OSError:
        return []
    found = []
    for key, (pattern, label) in CAPABILITY_PATTERNS.items():
        if re.search(pattern, sample, flags=re.IGNORECASE):
            found.append({"id": key, "label": label, "basis": "static_script_pattern", "confidence": "low"})
    return found


def _severity_for_mode(mode: int) -> str | None:
    if mode & stat.S_ISUID:
        return "high"
    if mode & stat.S_ISGID:
        return "medium"
    if mode & stat.S_IWOTH:
        return "medium"
    return None


def _security_posture() -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    firewall_tools = [name for name in ("ufw", "firewall-cmd", "nft", "iptables") if shutil.which(name)]
    firewall_active = False
    if shutil.which("ufw"):
        try:
            firewall_active = os.path.exists("/etc/ufw/ufw.conf") and "ENABLED=yes" in Path("/etc/ufw/ufw.conf").read_text(errors="ignore")
        except OSError:
            firewall_active = False
    if firewall_active:
        checks.append({"id": "firewall", "severity": "info", "status": "enabled", "title": "UFW firewall enabled", "evidence": "UFW configuration reports ENABLED=yes"})
    elif firewall_tools:
        checks.append({"id": "firewall", "severity": "medium", "status": "review", "title": "Firewall state needs verification", "evidence": "Firewall tooling is present, but an enabled state was not confirmed"})
    else:
        checks.append({"id": "firewall", "severity": "high", "status": "unknown", "title": "No supported firewall tool found", "evidence": "ufw, firewalld, nftables and iptables commands were not found"})

    ssh_path = Path("/etc/ssh/sshd_config")
    if ssh_path.is_file():
        try:
            ssh_text = "\n".join(
                line for line in ssh_path.read_text(errors="ignore").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
            root_lines = re.findall(r"^\s*PermitRootLogin\s+(\S+)", ssh_text, re.MULTILINE | re.IGNORECASE)
            if root_lines and root_lines[-1].lower() in {"yes", "without-password", "prohibit-password"}:
                checks.append({"id": "ssh-root-login", "severity": "medium", "status": "review", "title": "SSH root login may be permitted", "evidence": f"PermitRootLogin {root_lines[-1]} in sshd_config; included configuration may override this"})
            else:
                checks.append({"id": "ssh-root-login", "severity": "info", "status": "not-confirmed", "title": "SSH root login not explicitly enabled", "evidence": "No active PermitRootLogin yes directive was found in the main config"})
        except OSError:
            checks.append({"id": "ssh-root-login", "severity": "info", "status": "not-assessed", "title": "SSH configuration unreadable", "evidence": "Permission denied or file unavailable"})
    return {"checks": checks, "firewall_tools": firewall_tools}


def run_host_assessment(root: str = "/", *, max_files: int = MAX_FILES,
                        max_file_bytes: int = MAX_FILE_BYTES,
                        max_seconds: int = MAX_SECONDS) -> dict[str, Any]:
    """Hash eligible regular files under root and perform bounded read-only checks."""
    started = time.monotonic()
    root_path = Path(root).resolve()
    indicators = _load_indicators()
    findings: list[dict[str, Any]] = []
    capabilities: list[dict[str, str]] = []
    files_seen = 0
    files_hashed = 0
    bytes_hashed = 0
    skipped_large = 0
    skipped_unreadable = 0
    truncated = False
    errors: list[str] = []
    excluded = {str(root_path / item.lstrip("/")) for item in DEFAULT_EXCLUDES}

    for current, dirs, files in os.walk(root_path, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name for name in dirs
            if not (current_path / name).is_symlink()
            and str((current_path / name).resolve()) not in excluded
            and name not in {".git", "node_modules", ".venv", "venv", "__pycache__"}
            and not name.startswith(".cache")
        ]
        for name in files:
            if files_seen >= max_files or time.monotonic() - started >= max_seconds:
                truncated = True
                break
            path = current_path / name
            files_seen += 1
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > max_file_bytes:
                    if info.st_size > max_file_bytes:
                        skipped_large += 1
                    continue
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                sha256 = digest.hexdigest()
                files_hashed += 1
                bytes_hashed += info.st_size
                mode = stat.S_IMODE(info.st_mode)
                matched = indicators.get(sha256)
                if matched:
                    findings.append({
                        "id": f"hash-{sha256[:12]}", "category": "malware",
                        "severity": str(matched.get("severity", "critical")),
                        "title": str(matched.get("label", "Known malicious hash match")),
                        "description": str(matched.get("description", "SHA-256 matched a locally configured indicator.")),
                        "path": str(path), "sha256": sha256, "evidence": "exact_sha256_match",
                        "confidence": "high", "source": "local_hash_indicator",
                        "capabilities": matched.get("capabilities", []),
                    })
                mode_severity = _severity_for_mode(mode)
                if mode_severity:
                    findings.append({
                        "id": f"permission-{sha256[:12]}", "category": "configuration",
                        "severity": mode_severity, "title": "Sensitive permission bit or world-writable file",
                        "description": "Review this file's ownership and permissions; this is not by itself proof of compromise.",
                        "path": str(path), "sha256": sha256, "evidence": f"mode={oct(mode)}",
                        "confidence": "medium", "source": "filesystem_permission_audit",
                    })
                for capability in _script_capabilities(path):
                    capabilities.append({"path": str(path), **capability})
            except (OSError, PermissionError):
                skipped_unreadable += 1
        if truncated:
            break

    posture = _security_posture()
    findings.extend({
        "id": check["id"], "category": "configuration", "severity": check["severity"],
        "title": check["title"], "description": check["evidence"],
        "evidence": check["evidence"], "confidence": "medium" if check["severity"] in {"medium", "high"} else "high",
        "source": "local_security_configuration",
    } for check in posture["checks"] if check["severity"] in {"medium", "high"})

    return {
        "engine": "SENTINEL local read-only host assessment",
        "started_at": datetime.fromtimestamp(time.time() - (time.monotonic() - started), UTC).isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "scope": {"root": str(root_path), "excluded_directories": sorted(DEFAULT_EXCLUDES),
                  "max_files": max_files, "max_file_bytes": max_file_bytes, "max_seconds": max_seconds},
        "summary": {
            "files_seen": files_seen, "files_hashed": files_hashed, "bytes_hashed": bytes_hashed,
            "findings": len(findings), "malware_matches": sum(1 for item in findings if item["category"] == "malware"),
            "configuration_findings": sum(1 for item in findings if item["category"] == "configuration"),
            "truncated": truncated,
        },
        "findings": findings,
        "script_capabilities": capabilities,
        "security_posture": posture,
        "threat_intelligence": {
            "source": os.environ.get("SENTINEL_HASH_DB", "/etc/sentinel/hash_iocs.json"),
            "local_indicators_loaded": len(indicators),
            "network_lookup": False,
            "note": "No remote feed or built-in malware database is used. A hash match is exact; absence of a match does not establish that a file is safe.",
        },
        "limitations": [
            f"Skipped files larger than {max_file_bytes} bytes: {skipped_large}",
            f"Files that could not be read: {skipped_unreadable}",
            "Directories such as /proc, /sys, /dev, /run, caches and dependency trees are excluded.",
            "Static script patterns are leads, not proof of execution or malicious intent.",
            "A full filesystem scan may be truncated by the configured file-count or time budget.",
            "No files were executed, modified, quarantined, or uploaded.",
        ],
    }
