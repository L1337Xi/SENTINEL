"""Evidence-led file investigation and guarded local response actions."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import stat
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_BYTES = 64 * 1024 * 1024

def _run(args: list[str]) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=8, check=False)
        return p.stdout[:12000]
    except (OSError, subprocess.TimeoutExpired):
        return ""

def _hash(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("Only regular, non-symlink files are supported.")
    if info.st_size > MAX_BYTES:
        raise ValueError("File exceeds the 64 MiB response-action limit.")
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(chunk)
                md5.update(chunk)
    finally:
        os.close(fd)
    return sha.hexdigest(), md5.hexdigest(), info

def _package(path: Path, md5: str) -> dict[str, Any]:
    owner_text = _run(["dpkg-query", "-S", "--", str(path)])
    owner = owner_text.split(": ", 1)[0].split(", ", 1)[0] if owner_text else None
    if not owner:
        return {"owned": False, "integrity": "not_package_managed", "provenance": "unknown"}
    verify = _run(["dpkg", "-V", owner]).strip()
    conf = _run(["dpkg-query", "-W", "-f=${Conffiles}\\n", owner])
    expected = next((line.split()[1].lower() for line in conf.splitlines()
                     if len(line.split()) >= 2 and line.split()[0] == str(path)), None)
    checksum_match = expected == md5 if expected else None
    integrity = "verified" if not verify and (checksum_match is True or expected is None) else "mismatch"
    policy = _run(["apt-cache", "policy", owner])
    sources = [line.strip() for line in policy.splitlines() if "http://" in line or "https://" in line]
    return {"owned": True, "package": owner, "integrity": integrity,
            "dpkg_verify_output": verify[:2000] or None,
            "conffile_checksum_available": expected is not None,
            "conffile_checksum_match": checksum_match,
            "repository_sources": sources[:5],
            "provenance": "repository_source_listed" if sources else "not_confirmed"}

def investigate_file(path_value: str, expected_sha256: str | None = None) -> dict[str, Any]:
    path = Path(path_value)
    if not path.is_absolute():
        raise ValueError("Finding path must be absolute.")
    sha, md5, info = _hash(path)
    if expected_sha256 and sha != expected_sha256.lower():
        raise ValueError("File changed since scan; run a new assessment before taking action.")
    pkg = _package(path, md5)
    file_type = _run(["file", "-b", "--", str(path)]) or "unknown"
    if pkg["owned"] and pkg["integrity"] == "verified":
        verdict, confidence = "likely_false_positive", "high"
        rationale = "Package ownership and available integrity checks match. This supports a likely false positive, but does not prove harmlessness."
    elif pkg["owned"]:
        verdict, confidence = "needs_investigation", "medium"
        rationale = "A package-managed file failed an available integrity check. This is suspicious, not proof of malware."
    else:
        verdict, confidence = "unverified", "low"
        rationale = "No package-integrity context was available. Preserve the original detection as an unverified lead."
    return {"path": str(path), "sha256": sha, "md5": md5, "size_bytes": info.st_size,
            "file_type": file_type, "mode": oct(stat.S_IMODE(info.st_mode)),
            "package": pkg, "assessment": {"verdict": verdict, "confidence": confidence, "rationale": rationale},
            "analyzed_at": datetime.now(UTC).isoformat(),
            "limitations": ["Package verification is supporting evidence, not proof of safety.",
                            "The original antivirus detection is retained.", "No sample was executed or uploaded."]}

def _root() -> Path:
    return Path(os.environ.get("SENTINEL_QUARANTINE_DIR", "/var/lib/sentinel/quarantine")).resolve()

def _protected_path(path: Path) -> bool:
    resolved = path.resolve()
    protected = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
                 "/var/lib/dpkg", "/var/lib/sentinel")
    return any(resolved == Path(root) or Path(root) in resolved.parents for root in protected)

def quarantine_file(path_value: str, expected_sha256: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.is_absolute():
        raise ValueError("Finding path must be absolute.")
    if _protected_path(path):
        raise PermissionError("System and package configuration paths are protected from quarantine.")
    sha, md5, info = _hash(path)
    if sha != expected_sha256.lower():
        raise ValueError("File changed since scan; quarantine refused.")
    if _package(path, md5)["owned"]:
        raise PermissionError("Package-managed files are protected. Use the package manager.")
    if info.st_nlink > 1:
        raise PermissionError("Files with multiple hard links are protected.")
    root = _root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    item_id = str(uuid.uuid4())
    stored = root / item_id
    manifest = root / f"{item_id}.json"
    shutil.copy2(path, stored)
    os.chmod(stored, 0o600)
    if _hash(stored)[0] != sha:
        stored.unlink(missing_ok=True)
        raise OSError("Quarantine verification failed; original preserved.")
    record = {"id": item_id, "original_path": str(path), "sha256": sha,
              "size_bytes": info.st_size, "mode": stat.S_IMODE(info.st_mode),
              "uid": info.st_uid, "gid": info.st_gid,
              "quarantined_at": datetime.now(UTC).isoformat(), "status": "quarantined"}
    temp = manifest.with_suffix(".tmp")
    temp.write_text(json.dumps(record), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, manifest)
    path.unlink()
    return record

def list_quarantine() -> list[dict[str, Any]]:
    root = _root()
    if not root.is_dir():
        return []
    records = []
    for item in root.glob("*.json"):
        try:
            records.append(json.loads(item.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return records[:500]

def restore_quarantined(item_id: str) -> dict[str, Any]:
    normalized = str(uuid.UUID(item_id))
    root = _root()
    manifest = root / f"{normalized}.json"
    record = json.loads(manifest.read_text(encoding="utf-8"))
    stored = root / normalized
    original = Path(record["original_path"])
    if original.exists() or original.is_symlink():
        raise FileExistsError("Original path exists; restore will not overwrite it.")
    if _hash(stored)[0] != record["sha256"]:
        raise ValueError("Quarantine integrity check failed.")
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(stored, original)
    os.chown(original, int(record["uid"]), int(record["gid"]))
    os.chmod(original, int(record["mode"]))
    if _hash(original)[0] != record["sha256"]:
        original.unlink(missing_ok=True)
        raise OSError("Restored file failed verification.")
    stored.unlink()
    manifest.unlink()
    return {"id": normalized, "restored": True, "path": str(original), "sha256": record["sha256"]}

def permanently_delete_file(path_value: str, expected_sha256: str, confirmation: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.is_absolute(): raise ValueError("Finding path must be absolute.")
    if _protected_path(path):
        raise PermissionError("System and package configuration paths are protected from permanent deletion.")
    if confirmation != f"DELETE {expected_sha256.lower()}":
        raise PermissionError("The exact confirmation must be DELETE followed by the full SHA-256.")
    sha, md5, info = _hash(path)
    if sha != expected_sha256.lower():
        raise ValueError("File changed since scan; deletion refused.")
    if _package(path, md5)["owned"]:
        raise PermissionError("Package-managed files cannot be deleted by SENTINEL.")
    if info.st_nlink > 1:
        raise PermissionError("Files with multiple hard links are protected.")
    path.unlink()
    return {"deleted": True, "path": str(path), "sha256": sha, "deleted_at": datetime.now(UTC).isoformat()}
