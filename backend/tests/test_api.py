from app import database
from app.main import app
from fastapi.testclient import TestClient


def test_health():
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_event_ingest_list_and_filter(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.db")
    with TestClient(app) as client:
        created = client.post(
            "/api/events",
            json={
                "source": "pytest",
                "event_type": "authentication",
                "severity": "high",
                "message": "Repeated failed login attempts",
                "host": "lab-host",
                "occurred_at": "2026-11-17T12:00:00Z",
                "metadata": {"attempts": 8},
            },
        )
        assert created.status_code == 201
        event = created.json()
        assert event["metadata"]["attempts"] == 8
        listed = client.get("/api/events", params={"severity": "high", "search": "failed"})
        assert listed.status_code == 200
        assert listed.json()["total"] == 1
        assert listed.json()["items"][0]["id"] == event["id"]
        fetched = client.get(f"/api/events/{event['id']}")
        assert fetched.status_code == 200
        assert fetched.json()["source"] == "pytest"


def test_rejects_invalid_severity():
    with TestClient(app) as client:
        response = client.post("/api/events", json={
            "source": "pytest", "event_type": "test", "severity": "extreme", "message": "Invalid",
        })
    assert response.status_code == 422


def test_rejects_naive_timestamp():
    with TestClient(app) as client:
        response = client.post("/api/events", json={
            "source": "pytest", "event_type": "test", "message": "Missing timezone",
            "occurred_at": "2026-11-17T12:00:00",
        })
    assert response.status_code == 422


def test_scanner_network_scope_rejects_public_and_broad_ranges():
    from app.scanner import validate_local_network
    import pytest
    with pytest.raises(ValueError):
        validate_local_network("8.8.8.0/24")
    with pytest.raises(ValueError):
        validate_local_network("10.0.0.0/8")


def test_network_scan_rejects_unattached_range(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.db")
    with TestClient(app) as client:
        response = client.post("/api/scans/network", json={"network": "192.0.2.0/24"})
    assert response.status_code == 422


def test_network_schema_rejects_extra_fields():
    with TestClient(app) as client:
        response = client.post("/api/scans/network", json={"network": "192.168.1.0/24", "ports": [1, 2]})
    assert response.status_code == 422
