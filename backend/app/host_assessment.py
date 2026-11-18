"""Read-only local host security assessment.

The scanner never executes discovered files, changes host settings, quarantines files,
or uploads samples. Hash indicators may come from a local operator JSON file and an
optional, bounded MalwareBazaar metadata feed; no file contents leave the host.
"""
from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import selectors
import shutil
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .threat_intel import fetch_recent_malware, lookup_circl_hashes, match_recent_hashes

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
    "command_execution": (r"subprocess\.|os\.system|exec\(|popen\(|bash\s+-c|sh\s+-c|\|\s*(bash|sh)\b", "Command execution"),
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


def _clamav_scan(root: Path, timeout: int = 90,
                 progress_callback: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Run installed ClamAV locally and stream per-file progress without buffering the scan."""
    executable = shutil.which("clamscan")
    if not executable:
        return {"available": False, "executed": False, "findings": [],
                "files_scanned": 0, "current_path": None,
                "note": "ClamAV is not installed; SENTINEL did not install it."}
    version = None
    process = None
    detections: list[dict[str, Any]] = []
    files_scanned = 0
    current_path = None
    started = time.monotonic()
    try:
        version_result = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                         timeout=5, check=False)
        version = version_result.stdout.strip()[:200]
        process = subprocess.Popen(
            [executable, "--recursive", "--infected", "--no-summary", "--verbose",
             "--max-filesize=64M", "--max-scansize=2G",
             "--exclude-dir=^/(proc|sys|dev|run|var/cache|var/tmp)(/|$)", str(root)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
        )
        if process.stdout is None:
            raise OSError("ClamAV output stream was not available")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        pending = b""
        timed_out = False
        while selector.get_map():
            if time.monotonic() - started >= timeout:
                timed_out = True
                process.terminate()
                break
            ready = selector.select(timeout=0.2)
            if not ready and process.poll() is not None:
                break
            for key, _ in ready:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                pending += chunk
                while b"\n" in pending:
                    raw_line, pending = pending.split(b"\n", 1)
                    line = raw_line.decode(errors="replace").strip()
                    if not line:
                        continue
                    if line.endswith(" FOUND"):
                        files_scanned += 1
                        current_path = line.rsplit(": ", 1)[0]
                        file_path, signature = line.rsplit(": ", 1)
                        detections.append({
                            "id": f"clamav-{hashlib.sha256(line.encode()).hexdigest()[:12]}",
                            "category": "malware", "severity": "high",
                            "title": signature.removesuffix(" FOUND"),
                            "description": "ClamAV signature detection. Treat as a strong lead and preserve the sample for controlled analysis.",
                            "path": file_path, "evidence": line, "confidence": "high",
                            "source": "clamav", "engine": "ClamAV",
                        })
                        if progress_callback:
                            progress_callback({"current_path": current_path,
                                               "clamav_files_scanned": files_scanned})
                    elif line.endswith(": OK"):
                        current_path = line.rsplit(": ", 1)[0]
                        files_scanned += 1
                        if progress_callback:
                            progress_callback({"current_path": current_path,
                                               "clamav_files_scanned": files_scanned})
                    elif line.startswith(("Scanning:", "Scanning ")):
                        current_path = line.partition(":")[2].strip() if line.startswith("Scanning:") else line.removeprefix("Scanning ").strip()
                        if progress_callback:
                            progress_callback({"current_path": current_path,
                                               "clamav_files_scanned": files_scanned})
        selector.close()
        if timed_out:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            return {"available": True, "executed": True, "version": version,
                    "findings": detections, "files_scanned": files_scanned,
                    "current_path": current_path, "timed_out": True,
                    "note": f"ClamAV exceeded its {timeout}-second time limit; results are incomplete."}
        if pending:
            line = pending.decode(errors="replace").strip()
            if line.endswith(" FOUND"):
                files_scanned += 1
                current_path = line.rsplit(": ", 1)[0]
                file_path, signature = line.rsplit(": ", 1)
                detections.append({
                    "id": f"clamav-{hashlib.sha256(line.encode()).hexdigest()[:12]}",
                    "category": "malware", "severity": "high",
                    "title": signature.removesuffix(" FOUND"),
                    "description": "ClamAV signature detection. Treat as a strong lead and preserve the sample for controlled analysis.",
                    "path": file_path, "evidence": line, "confidence": "high",
                    "source": "clamav", "engine": "ClamAV",
                })
        return {"available": True, "executed": True, "version": version,
                "return_code": process.wait(), "findings": detections,
                "files_scanned": files_scanned, "current_path": current_path,
                "note": "ClamAV ran locally with existing signatures; no signature update or network lookup was performed."}
    except subprocess.TimeoutExpired:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        return {"available": True, "executed": True, "version": version,
                "findings": detections, "files_scanned": files_scanned,
                "current_path": current_path, "timed_out": True,
                "note": f"ClamAV exceeded its {timeout}-second time limit; results are incomplete."}
    except OSError as exc:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        return {"available": True, "executed": False, "findings": detections,
                "files_scanned": files_scanned, "current_path": current_path,
                "note": f"ClamAV could not be started: {str(exc)[:200]}"}

def _severity_for_mode(mode: int) -> str | None:
    if mode & stat.S_ISUID:
        return "high"
    if mode & stat.S_ISGID:
        return "medium"
    if mode & stat.S_IWOTH and mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return "medium"
    return None


def _persistence_inventory() -> list[dict[str, str]]:
    """Inventory common Linux startup locations without executing or changing entries."""
    roots = [
        Path("/etc/systemd/system"), Path("/usr/lib/systemd/system"),
        Path("/lib/systemd/system"), Path("/etc/cron.d"), Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"), Path("/etc/cron.weekly"), Path("/etc/cron.monthly"),
        Path("/etc/xdg/autostart"), Path("/etc/init.d"),
    ]
    entries: list[dict[str, str]] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for item in sorted(root.iterdir()):
                if item.is_file() or item.is_symlink():
                    entries.append({"path": str(item), "category": root.name,
                                    "type": "symlink" if item.is_symlink() else "file"})
                if len(entries) >= 1000:
                    return entries
        except OSError:
            continue
    try:
        for home in Path("/home").iterdir():
            for item in (home / ".config" / "autostart").glob("*.desktop"):
                entries.append({"path": str(item), "category": "user-autostart", "type": "file"})
                if len(entries) >= 1000:
                    return entries
    except OSError:
        pass
    return entries


def _privileged_account_inventory() -> dict[str, Any]:
    uid_zero = []
    for account in pwd.getpwall():
        if account.pw_uid == 0:
            uid_zero.append({"username": account.pw_name, "uid": account.pw_uid,
                             "home": account.pw_dir, "shell": account.pw_shell})
    privileged_groups = []
    for group_name in ("sudo", "wheel", "admin"):
        try:
            group = grp.getgrnam(group_name)
        except KeyError:
            continue
        privileged_groups.append({"group": group_name, "members": sorted(set(group.gr_mem))})
    return {"uid_zero_accounts": uid_zero, "privileged_groups": privileged_groups}


def _security_posture() -> dict[str, Any]:
    """Inspect host INPUT policy without mistaking Docker forwarding/NAT rules for a host firewall."""
    checks: list[dict[str, str]] = []
    firewall_tools = [
        name for name in ("ufw", "firewall-cmd", "nft", "iptables")
        if shutil.which(name)
    ]
    evidence: list[str] = []
    ufw_active = False
    nft_input_default_deny = False
    nft_input_filter_rules = False
    iptables_input_default_deny = False
    iptables_input_filter_rules = False
    inspected = False

    def read_command(args: list[str]) -> str:
        try:
            completed = subprocess.run(
                args, capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        if completed.returncode == 0:
            return completed.stdout
        return ""

    if shutil.which("ufw"):
        output = read_command(["ufw", "status"])
        if output:
            inspected = True
            status = re.search(r"^Status:\s*(active|inactive)\s*$", output, re.MULTILINE | re.IGNORECASE)
            if status and status.group(1).lower() == "active":
                ufw_active = True
                evidence.append("UFW reports Status: active")
            elif status:
                evidence.append("UFW reports Status: inactive")

    if shutil.which("nft"):
        output = read_command(["nft", "-n", "list", "ruleset"])
        if output:
            inspected = True
            # Only inspect base chains attached to the host INPUT hook. Docker's
            # NAT and FORWARD chains are deliberately not treated as host protection.
            for match in re.finditer(r"\bchain\s+([^\s{]+)\s*\{([^}]*)\}", output, re.DOTALL):
                body = match.group(2)
                if not re.search(r"\bhook\s+input\b", body):
                    continue
                policy = re.search(r"\bpolicy\s+(drop|reject|accept)\b", body)
                if policy and policy.group(1) in {"drop", "reject"}:
                    nft_input_default_deny = True
                    evidence.append(f"nftables INPUT base chain {match.group(1)} has policy {policy.group(1)}")
                if re.search(r"\b(drop|reject)\b", body):
                    nft_input_filter_rules = True
                    evidence.append(f"nftables INPUT base chain {match.group(1)} contains drop/reject rules")

    if shutil.which("iptables"):
        output = read_command(["iptables", "-S", "INPUT"])
        if output:
            inspected = True
            policy = re.search(r"^-P\s+INPUT\s+(DROP|REJECT|ACCEPT)\s*$", output, re.MULTILINE)
            if policy and policy.group(1) in {"DROP", "REJECT"}:
                iptables_input_default_deny = True
                evidence.append(f"iptables INPUT default policy is {policy.group(1)}")
            if re.search(r"^-A\s+INPUT\b.*\s-j\s+(DROP|REJECT)\b", output, re.MULTILINE):
                iptables_input_filter_rules = True
                evidence.append("iptables INPUT chain contains explicit DROP/REJECT rules")

    if ufw_active or nft_input_default_deny or iptables_input_default_deny:
        checks.append({
            "id": "firewall", "severity": "info", "status": "enabled",
            "title": "Host inbound firewall policy detected",
            "evidence": "; ".join(evidence) or "A host INPUT default-deny policy was detected",
        })
    elif nft_input_filter_rules or iptables_input_filter_rules:
        checks.append({
            "id": "firewall", "severity": "medium", "status": "partial",
            "title": "Host firewall rules detected; default policy needs review",
            "evidence": "; ".join(evidence) or "Explicit INPUT filtering rules were detected",
        })
    elif inspected:
        checks.append({
            "id": "firewall", "severity": "medium", "status": "inactive",
            "title": "Host inbound firewall protection not confirmed",
            "evidence": "; ".join(evidence) or (
                "No active UFW policy or INPUT default-deny policy was detected. "
                "Docker NAT/FORWARD rules do not establish host INPUT protection."
            ),
        })
    else:
        checks.append({
            "id": "firewall", "severity": "info", "status": "unknown",
            "title": "Host firewall state could not be assessed",
            "evidence": "No supported firewall command returned inspectable rules or status",
        })

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
                        max_seconds: int = MAX_SECONDS,
                        progress_callback: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Hash eligible regular files under root and perform bounded read-only checks."""
    started = time.monotonic()
    root_path = Path(root).resolve()
    indicators = _load_indicators()
    findings: list[dict[str, Any]] = []
    scanned_hashes: dict[str, list[str]] = {}
    capabilities: list[dict[str, str]] = []
    files_seen = 0
    files_hashed = 0
    bytes_hashed = 0
    skipped_large = 0
    skipped_unreadable = 0
    truncated = False
    excluded = {str(root_path / item.lstrip("/")) for item in DEFAULT_EXCLUDES}
    last_progress_at = 0.0

    def report_progress(phase: str, current_path: str | None = None, *, force: bool = False) -> None:
        nonlocal last_progress_at
        if progress_callback is None:
            return
        elapsed = time.monotonic() - started
        if not force and files_seen % 100 != 0 and elapsed - last_progress_at < 0.75:
            return
        last_progress_at = elapsed
        progress_callback({
            "phase": phase, "current_path": current_path,
            "files_seen": files_seen, "files_hashed": files_hashed,
            "bytes_hashed": bytes_hashed,
            "malware_matches": sum(1 for item in findings if item.get("category") == "malware"),
            "script_indicators": len(capabilities),
            "elapsed_seconds": round(elapsed, 1),
            "time_budget_seconds": max_seconds,
            "time_budget_remaining": round(max(0.0, max_seconds - elapsed), 1),
        })

    report_progress("filesystem", str(root_path), force=True)
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
            report_progress("filesystem", str(path))
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
                scanned_hashes.setdefault(sha256, []).append(str(path))
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
                        "severity": mode_severity, "title": "Sensitive permission bit or world-writable executable",
                        "description": "Review this executable's ownership and permissions; this is not by itself proof of compromise.",
                        "path": str(path), "sha256": sha256, "evidence": f"mode={oct(mode)}",
                        "confidence": "medium", "source": "filesystem_permission_audit",
                    })
                for capability in _script_capabilities(path):
                    capabilities.append({"path": str(path), **capability})
            except (OSError, PermissionError):
                skipped_unreadable += 1
        if truncated:
            break

    report_progress("threat_intelligence", None, force=True)
    malwarebazaar = fetch_recent_malware()
    findings.extend(match_recent_hashes(scanned_hashes, malwarebazaar))
    circl = lookup_circl_hashes(scanned_hashes)

    clamav_files_scanned = 0
    def report_clamav_progress(update: dict[str, Any]) -> None:
        nonlocal clamav_files_scanned
        clamav_files_scanned = int(update.get("clamav_files_scanned", clamav_files_scanned))
        report_progress("clamav", update.get("current_path"), force=True)
        if progress_callback:
            progress_callback({
                "phase": "clamav", "current_path": update.get("current_path"),
                "files_seen": files_seen, "files_hashed": files_hashed,
                "bytes_hashed": bytes_hashed, "malware_matches": sum(1 for item in findings if item.get("category") == "malware"),
                "script_indicators": len(capabilities), "clamav_files_scanned": clamav_files_scanned,
                "elapsed_seconds": round(time.monotonic() - started, 1),
                "time_budget_seconds": max_seconds,
                "time_budget_remaining": round(max(0.0, max_seconds - (time.monotonic() - started)), 1),
            })
    report_progress("clamav", None, force=True)
    clamav = _clamav_scan(root_path, progress_callback=report_clamav_progress)
    findings.extend(clamav["findings"])
    report_progress("configuration", None, force=True)
    posture = _security_posture()
    persistence = _persistence_inventory()
    accounts = _privileged_account_inventory()
    findings.extend({
        "id": check["id"], "category": "configuration", "severity": check["severity"],
        "title": check["title"], "description": check["evidence"],
        "evidence": check["evidence"], "confidence": "medium" if check["severity"] in {"medium", "high"} else "high",
        "source": "local_security_configuration",
    } for check in posture["checks"] if check["severity"] in {"medium", "high"})

    report_progress("completed", None, force=True)
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
        "persistence_inventory": persistence,
        "privileged_accounts": accounts,
        "malware_engines": {"clamav": {key: value for key, value in clamav.items() if key != "findings"}},
        "threat_intelligence": {
            "local_indicator_source": os.environ.get("SENTINEL_HASH_DB", "/etc/sentinel/hash_iocs.json"),
            "local_indicators_loaded": len(indicators),
            "network_lookup": malwarebazaar.get("status") in {"ok", "stale"} or circl.get("lookups_performed", 0) > 0,
            "malwarebazaar": {key: value for key, value in malwarebazaar.items() if key != "entries"},
            "circl_hashlookup": {key: value for key, value in circl.items() if key != "matches"},
            "known_file_context": circl.get("matches", []),
            "note": "MalwareBazaar checks only its latest 100 additions. CIRCL hashlookup provides known-file context only, not a malware verdict. No match from either source establishes that a file is safe.",
        },
        "limitations": [
            f"Skipped files larger than {max_file_bytes} bytes: {skipped_large}",
            f"Files that could not be read: {skipped_unreadable}",
            "Directories such as /proc, /sys, /dev, /run, caches and dependency trees are excluded.",
            "Static script patterns are leads, not proof of execution or malicious intent.",
            "A full filesystem scan may be truncated by the configured file-count or time budget.",
            "CIRCL receives only the bounded SHA-256 lookup values; local file paths and file contents are not transmitted.",
            "No files were executed, modified, quarantined, or uploaded.",
        ],
    }
