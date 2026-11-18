import pytest
from app import database
from app.main import app
from app.scanner import validate_local_network
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


def test_scanner_rejects_ipv6_networks():
    with pytest.raises(TypeError):
        validate_local_network("fd00::/64")



def test_detection_creates_alert_and_supports_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "alerts.db")
    with TestClient(app) as client:
        created = client.post(
            "/api/events",
            json={
                "source": "auth-agent",
                "event_type": "authentication_failure",
                "severity": "medium",
                "message": "Repeated login failures",
                "host": "lab-host",
                "metadata": {"failed_attempts": 7},
            },
        )
        assert created.status_code == 201
        alerts = client.get("/api/alerts", params={"status": "open"})
        assert alerts.status_code == 200
        assert alerts.json()["total"] == 1
        alert = alerts.json()["items"][0]
        assert alert["rule_id"] == "AUTH-001"
        assert alert["severity"] == "high"
        updated = client.patch(
            f"/api/alerts/{alert['id']}", json={"status": "acknowledged"}
        )
        assert updated.status_code == 200
        assert updated.json()["status"] == "acknowledged"
        resolved = client.patch(
            f"/api/alerts/{alert['id']}", json={"status": "resolved"}
        )
        assert resolved.status_code == 200
        assert resolved.json()["status"] == "resolved"


def test_detection_ignores_auth_events_below_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "no-alert.db")
    with TestClient(app) as client:
        response = client.post(
            "/api/events",
            json={
                "source": "auth-agent",
                "event_type": "authentication_failure",
                "message": "Single failed login",
                "metadata": {"attempts": 2},
            },
        )
        assert response.status_code == 201
        assert client.get("/api/alerts").json()["total"] == 0


def test_audit_log_records_event_alert_creation_and_status_transitions(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "audit.db")
    with TestClient(app) as client:
        created = client.post(
            "/api/events",
            json={
                "source": "auth-agent",
                "event_type": "authentication_failure",
                "message": "Repeated login failures",
                "metadata": {"attempts": 9},
            },
        )
        assert created.status_code == 201
        alert = client.get("/api/alerts").json()["items"][0]

        acknowledged = client.patch(
            "/api/alerts/" + alert["id"], json={"status": "acknowledged"}
        )
        assert acknowledged.status_code == 200
        resolved = client.patch(
            "/api/alerts/" + alert["id"], json={"status": "resolved"}
        )
        assert resolved.status_code == 200

        audit = client.get("/api/audit-log").json()["items"]
        actions = [item["action"] for item in audit]
        assert actions.count("event.ingested") == 1
        assert actions.count("alert.created") == 1
        assert actions.count("alert.status_changed") == 2
        transitions = [item["details"] for item in audit if item["action"] == "alert.status_changed"]
        assert transitions == [
            {"from": "acknowledged", "to": "resolved"},
            {"from": "open", "to": "acknowledged"},
        ]

        filtered = client.get("/api/audit-log", params={"entity_type": "alert"})
        assert filtered.status_code == 200
        assert all(item["entity_type"] == "alert" for item in filtered.json()["items"])


def test_audit_log_does_not_duplicate_noop_status_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "audit-noop.db")
    with TestClient(app) as client:
        created = client.post(
            "/api/events",
            json={
                "source": "auth-agent",
                "event_type": "authentication_failure",
                "message": "Repeated login failures",
                "metadata": {"attempts": 6},
            },
        )
        alert = client.get("/api/alerts").json()["items"][0]
        client.patch("/api/alerts/" + alert["id"], json={"status": "acknowledged"})
        before = client.get("/api/audit-log").json()["total"]
        client.patch("/api/alerts/" + alert["id"], json={"status": "acknowledged"})
        after = client.get("/api/audit-log").json()["total"]
        assert created.status_code == 201
        assert before == after


def test_incident_case_lifecycle_links_events_and_records_timeline(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "cases.db")
    with TestClient(app) as client:
        event = client.post("/api/events", json={
            "source":"auth-agent","event_type":"authentication_failure",
            "message":"Repeated login failures","metadata":{"attempts":8},
        })
        case_response = client.post("/api/cases", json={
            "title":"Investigate repeated authentication failures",
            "description":"Initial triage for lab host.","severity":"high",
        })
        assert event.status_code == 201 and case_response.status_code == 201
        case = case_response.json()
        assert case["status"] == "open"
        event_id = event.json()["id"]
        assert client.post(f"/api/cases/{case['id']}/events",json={"event_id":event_id}).status_code == 201
        assert client.post(f"/api/cases/{case['id']}/events",json={"event_id":event_id}).status_code == 201
        assert client.post(f"/api/cases/{case['id']}/notes",json={"content":"Validate source IP."}).status_code == 201
        updated = client.patch(f"/api/cases/{case['id']}",json={"status":"investigating","severity":"critical"})
        assert updated.status_code == 200
        detail = client.get(f"/api/cases/{case['id']}").json()
        assert len(detail["events"]) == 1 and detail["events"][0]["id"] == event_id
        timeline = client.get(f"/api/cases/{case['id']}/timeline").json()["items"]
        assert [x["entry_type"] for x in timeline] == ["case.updated","note.added","event.linked","case.created"]
        assert client.get("/api/audit-log",params={"entity_type":"case"}).status_code == 200


def test_case_validation_filters_and_close_reopen(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "case-validation.db")
    with TestClient(app) as client:
        assert client.post("/api/cases",json={"title":"  "}).status_code == 422
        high = client.post("/api/cases",json={"title":"High priority case","severity":"high"}).json()
        client.post("/api/cases",json={"title":"Low priority case","severity":"low"})
        assert client.get("/api/cases",params={"severity":"high"}).json()["total"] == 1
        closed = client.patch(f"/api/cases/{high['id']}",json={"status":"resolved"}).json()
        assert closed["closed_at"] is not None
        reopened = client.patch(f"/api/cases/{high['id']}",json={"status":"investigating"}).json()
        assert reopened["closed_at"] is None
        assert client.patch(f"/api/cases/{high['id']}",json={}).status_code == 422
        assert client.get("/api/cases/not-a-uuid").status_code == 404


def test_host_scan_history_delete_is_scoped_and_protects_active_and_network_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "scan-delete.db")
    host_id = "11111111-1111-4111-8111-111111111111"
    network_id = "22222222-2222-4222-8222-222222222222"
    active_id = "33333333-3333-4333-8333-333333333333"
    with TestClient(app) as client:
        database.create_scan(host_id, "system", "This machine", "2026-11-18T10:00:00+00:00")
        database.update_scan(host_id, status="completed", result={"hostname": "test"})
        database.create_scan(network_id, "network", "192.168.1.0/24", "2026-11-18T10:01:00+00:00")
        database.update_scan(network_id, status="completed", result={"responsive_hosts": 1})
        database.create_scan(active_id, "system", "This machine", "2026-11-18T10:02:00+00:00")
        database.update_scan(active_id, status="running", progress={"phase": "filesystem"})

        deleted = client.delete(f"/api/scans/{host_id}")
        assert deleted.status_code == 200
        assert deleted.json()["deleted"] is True
        assert client.get(f"/api/scans/{host_id}").status_code == 404
        assert client.get(f"/api/scans/{network_id}").status_code == 200

        protected_network = client.delete(f"/api/scans/{network_id}")
        protected_active = client.delete(f"/api/scans/{active_id}")
        assert protected_network.status_code == 409
        assert protected_active.status_code == 409
        assert client.get(f"/api/scans/{active_id}").status_code == 200
        audit = database.list_audit_log(10, "scan")
        assert any(row["action"] == "scan.deleted" and row["entity_id"] == host_id for row in audit)
        filtered_audit = client.get("/api/audit-log", params={"entity_type": "scan"})
        assert filtered_audit.status_code == 200
        assert filtered_audit.json()["total"] >= 1


def test_clear_host_scan_history_preserves_network_and_active_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "clear-scan-history.db")
    completed_id = "44444444-4444-4444-8444-444444444444"
    failed_id = "55555555-5555-4555-8555-555555555555"
    network_id = "66666666-6666-4666-8666-666666666666"
    active_id = "77777777-7777-4777-8777-777777777777"
    with TestClient(app) as client:
        for scan_id, scan_type, status, target in [
            (completed_id, "system", "completed", "This machine"),
            (failed_id, "system", "failed", "This machine"),
            (network_id, "network", "completed", "192.168.1.0/24"),
            (active_id, "system", "running", "This machine"),
        ]:
            database.create_scan(scan_id, scan_type, target, "2026-11-18T10:00:00+00:00")
            database.update_scan(scan_id, status=status, result={"test": True} if status == "completed" else None)

        response = client.delete("/api/scans/system")
        assert response.status_code == 200
        assert response.json()["deleted"] == 2
        assert client.get(f"/api/scans/{completed_id}").status_code == 404
        assert client.get(f"/api/scans/{failed_id}").status_code == 404
        assert client.get(f"/api/scans/{network_id}").status_code == 200
        assert client.get(f"/api/scans/{active_id}").status_code == 200
        audit = database.list_audit_log(10, "scan")
        assert any(row["action"] == "scan.history_cleared" for row in audit)
