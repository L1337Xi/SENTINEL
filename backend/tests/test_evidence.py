import hashlib

import pytest
from app import config, database
from app.main import app
from fastapi.testclient import TestClient

PAYLOAD = b"SENTINEL synthetic evidence sample\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "evidence.db")
    monkeypatch.setattr(config, "EVIDENCE_DIR", tmp_path / "store")
    with TestClient(app) as test_client:
        yield test_client


def upload(client, name="sample.txt", payload=PAYLOAD, **data):
    return client.post(
        "/api/evidence",
        files={"file": (name, payload, "text/plain")},
        data=data or {"source": "pytest"},
    )


def test_acquire_hashes_stores_and_verifies(client):
    created = upload(client)
    assert created.status_code == 201
    item = created.json()
    assert item["sha256"] == DIGEST
    assert item["size_bytes"] == len(PAYLOAD)
    assert item["status"] == "acquired"
    assert item["original_name"] == "sample.txt"
    assert item["object_ref"] == f"objects/{DIGEST[:2]}/{DIGEST}"
    assert "storage_path" not in item

    verified = client.post(f"/api/evidence/{item['id']}/verify")
    assert verified.status_code == 200
    result = verified.json()
    assert result["verified"] is True
    assert result["status"] == "verified"
    assert result["observed_sha256"] == DIGEST

    detail = client.get(f"/api/evidence/{item['id']}").json()
    assert detail["status"] == "verified"
    assert detail["verify_count"] == 1
    assert [entry["action"] for entry in detail["custody"]] == ["verified", "acquired"]
    assert all(entry["sha256"] == DIGEST for entry in detail["custody"])

    audit = client.get("/api/audit-log", params={"entity_type": "evidence"}).json()["items"]
    actions = [entry["action"] for entry in audit]
    assert "evidence.acquired" in actions and "evidence.verified" in actions


def test_duplicate_acquisition_is_rejected(client):
    first = upload(client)
    second = upload(client, name="copy.txt")
    assert first.status_code == 201
    assert second.status_code == 409
    detail = second.json()["detail"]
    assert detail["existing_evidence_id"] == first.json()["id"]
    assert detail["sha256"] == DIGEST
    assert client.get("/api/evidence").json()["total"] == 1


def test_empty_and_oversized_uploads_are_rejected(client, monkeypatch):
    assert upload(client, payload=b"").status_code == 422
    monkeypatch.setattr(config, "MAX_EVIDENCE_BYTES", 8)
    assert upload(client, payload=b"0123456789").status_code == 413
    assert client.get("/api/evidence").json()["total"] == 0


def test_case_link_creates_custody_and_timeline(client):
    case = client.post(
        "/api/cases", json={"title": "Evidence intake", "severity": "medium"}
    ).json()
    item = upload(client).json()
    linked = client.post(f"/api/evidence/{item['id']}/case", json={"case_id": case["id"]})
    assert linked.status_code == 201
    assert linked.json() == {
        "evidence_id": item["id"], "case_id": case["id"], "linked": True
    }
    assert client.get(f"/api/evidence/{item['id']}").json()["case_id"] == case["id"]
    case_evidence = client.get(f"/api/cases/{case['id']}/evidence").json()
    assert case_evidence["total"] == 1
    assert case_evidence["items"][0]["id"] == item["id"]
    timeline = client.get(f"/api/cases/{case['id']}/timeline").json()["items"]
    assert "evidence.linked" in [entry["entry_type"] for entry in timeline]
    assert client.post(
        f"/api/evidence/{item['id']}/case",
        json={"case_id": "00000000-0000-0000-0000-000000000000"},
    ).status_code == 404


def test_custody_actions_require_known_evidence_and_valid_action(client):
    item = upload(client).json()
    rejected = client.post(
        f"/api/evidence/{item['id']}/custody", json={"action": "destroyed", "note": "nope"}
    )
    assert rejected.status_code == 422
    accepted = client.post(
        f"/api/evidence/{item['id']}/custody",
        json={"action": "transferred", "note": "Handed to analysis workstation.", "actor": "pytest"},
    )
    assert accepted.status_code == 201
    assert accepted.json()["custody_entry"]["action"] == "transferred"
    assert accepted.json()["custody_entry"]["actor"] == "pytest"
    released = client.post(
        f"/api/evidence/{item['id']}/custody",
        json={"action": "released", "note": "Returned to owner."},
    )
    assert released.json()["evidence"]["status"] == "released"
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.post(
        f"/api/evidence/{missing}/custody", json={"action": "note", "note": "x"}
    ).status_code == 404
    assert client.get("/api/evidence/not-a-uuid").status_code == 404


def test_tampered_object_is_detected_without_rewriting_it(client, tmp_path):
    item = upload(client).json()
    blob = tmp_path / "store" / "objects" / DIGEST[:2] / DIGEST
    blob.chmod(0o600)
    blob.write_bytes(b"altered evidence")
    result = client.post(f"/api/evidence/{item['id']}/verify").json()
    assert result["verified"] is False
    assert result["status"] == "tampered"
    assert result["observed_sha256"] != result["expected_sha256"]
    detail = client.get(f"/api/evidence/{item['id']}").json()
    assert detail["custody"][0]["action"] == "verify_failed"
    assert "INTEGRITY FAILURE" in detail["custody"][0]["note"]
    audit = client.get("/api/audit-log", params={"entity_type": "evidence"}).json()["items"]
    assert "evidence.integrity_failed" in [entry["action"] for entry in audit]


def test_missing_object_is_reported(client, tmp_path):
    item = upload(client).json()
    blob = tmp_path / "store" / "objects" / DIGEST[:2] / DIGEST
    blob.unlink()
    result = client.post(f"/api/evidence/{item['id']}/verify").json()
    assert result["verified"] is False
    assert result["status"] == "missing"
    assert client.get(f"/api/evidence/{item['id']}").json()["status"] == "missing"


def test_list_filters_by_status_and_hash(client):
    item = upload(client).json()
    upload(client, name="other.txt", payload=b"different bytes")
    assert client.get("/api/evidence", params={"status": "acquired"}).json()["total"] == 2
    assert client.get("/api/evidence", params={"sha256": DIGEST}).json()["total"] == 1
    assert client.get("/api/evidence", params={"status": "verified"}).json()["total"] == 0
    client.post(f"/api/evidence/{item['id']}/verify")
    assert client.get("/api/evidence", params={"status": "verified"}).json()["total"] == 1
    assert client.get("/api/evidence", params={"sha256": "not-a-digest"}).status_code == 422
