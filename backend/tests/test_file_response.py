import hashlib
import pytest

from app import file_response


def test_investigation_reports_verified_package_as_likely_false_positive(tmp_path, monkeypatch):
    sample = tmp_path / "payloads.conf"
    sample.write_text("legitimate scanner payload")
    digest = hashlib.md5(sample.read_bytes(), usedforsecurity=False).hexdigest()
    monkeypatch.setattr(file_response, "_package", lambda path, md5: {
        "owned": True, "package": "unicornscan", "integrity": "verified",
        "conffile_checksum_match": md5 == digest, "provenance": "repository_source_listed",
    })
    monkeypatch.setattr(file_response, "_run", lambda args: "ASCII text" if args[0] == "file" else "")
    report = file_response.investigate_file(str(sample), hashlib.sha256(sample.read_bytes()).hexdigest())
    assert report["assessment"]["verdict"] == "likely_false_positive"
    assert report["assessment"]["confidence"] == "high"
    assert report["package"]["package"] == "unicornscan"
    assert sample.exists()


def test_investigation_refuses_changed_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed since scan"):
        file_response.investigate_file(str(sample), hashlib.sha256(b"old").hexdigest())


def test_quarantine_and_restore_verify_hash_and_preserve_original_path(tmp_path, monkeypatch):
    sample = tmp_path / "suspicious.bin"
    payload = b"synthetic suspicious fixture"
    sample.write_bytes(payload)
    monkeypatch.setenv("SENTINEL_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setattr(file_response, "_package", lambda path, md5: {"owned": False})
    digest = hashlib.sha256(payload).hexdigest()

    result = file_response.quarantine_file(str(sample), digest)
    assert result["status"] == "quarantined"
    assert not sample.exists()
    assert file_response.list_quarantine()[0]["sha256"] == digest

    restored = file_response.restore_quarantined(result["id"])
    assert restored["restored"] is True
    assert sample.read_bytes() == payload
    assert file_response.list_quarantine() == []


def test_quarantine_protects_package_managed_files(tmp_path, monkeypatch):
    sample = tmp_path / "managed.conf"
    sample.write_text("package-owned")
    monkeypatch.setattr(file_response, "_package", lambda path, md5: {"owned": True})
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    with pytest.raises(PermissionError, match="Package-managed"):
        file_response.quarantine_file(str(sample), digest)
    assert sample.exists()


def test_permanent_delete_requires_exact_confirmation_and_blocks_packages(tmp_path, monkeypatch):
    sample = tmp_path / "managed.conf"
    sample.write_text("package-owned")
    monkeypatch.setattr(file_response, "_package", lambda path, md5: {"owned": True})
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    with pytest.raises(PermissionError, match="Package-managed"):
        file_response.permanently_delete_file(str(sample), digest, f"DELETE {digest}")
    assert sample.exists()


def test_permanent_delete_requires_hash_confirmation_for_unmanaged_file(tmp_path, monkeypatch):
    sample = tmp_path / "unmanaged.bin"
    sample.write_bytes(b"delete fixture")
    monkeypatch.setattr(file_response, "_package", lambda path, md5: {"owned": False})
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    with pytest.raises(PermissionError, match="exact confirmation"):
        file_response.permanently_delete_file(str(sample), digest, "yes")
    result = file_response.permanently_delete_file(str(sample), digest, f"DELETE {digest}")
    assert result["deleted"] is True
    assert not sample.exists()
