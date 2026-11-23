from io import BytesIO
from urllib.error import HTTPError

import pytest
from app import router_integration


def test_router_url_requires_private_ipv4():
    with pytest.raises(ValueError):
        router_integration.inspect_router_login("http://example.com/login")
    with pytest.raises(ValueError):
        router_integration.inspect_router_login("http://8.8.8.8/")
    with pytest.raises(ValueError):
        router_integration.inspect_router_login("http://127.0.0.1/")
    with pytest.raises(ValueError):
        router_integration.inspect_router_login("ftp://192.168.1.1/")


def test_router_login_probe_detects_page_without_submitting_credentials(monkeypatch):
    class Response:
        status = 200
        def __init__(self):
            self.headers = {"Content-Type": "text/html"}

        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self, limit):
            return b'<html><head><title>TP-Link Login</title></head><body><form><input name="user"><input type="password" name="pass"></form></body></html>'
        def geturl(self):
            return "http://192.168.1.1/admin/login.asp"

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "http://192.168.1.1/admin/login.asp"
            assert timeout == 4
            return Response()

    monkeypatch.setattr(router_integration, "build_opener", lambda *handlers: Opener())
    result = router_integration.inspect_router_login("192.168.1.1/admin/login.asp")
    assert result["reachable"] is True
    assert result["login_form_detected"] is True
    assert result["vendor_hint"] == "tp-link"
    assert result["password_fields"] == 1
    assert "not submitted or stored" in result["security_note"]


def test_router_probe_does_not_follow_redirects(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 302, "Redirect", {}, BytesIO())

    monkeypatch.setattr(router_integration, "build_opener", lambda *handlers: Opener())
    result = router_integration.inspect_router_login("http://192.168.1.1/")
    assert result["status"] == "redirect_not_followed"
    assert result["capabilities"] == []



def test_router_probe_api_returns_discovery_result(monkeypatch):
    from app import main
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "inspect_router_login", lambda address: {
        "reachable": True, "status": "login_page_detected", "http_status": 200,
        "final_url": address, "title": "Router Login", "login_form_detected": True,
        "capabilities": [], "message": "Login page detected.",
    })
    with TestClient(main.app) as client:
        response = client.post("/api/network/router/probe", json={"address": "192.168.1.1"})
    assert response.status_code == 200
    assert response.json()["login_form_detected"] is True


def test_router_probe_api_rejects_invalid_address():
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.post("/api/network/router/probe", json={"address": "https://example.com"})
    assert response.status_code == 422



def test_router_login_uses_only_same_origin_standard_post_form(monkeypatch):
    login_page = b'<html><title>Router</title><form method="post" action="/login"><input type="hidden" name="csrf" value="abc"><input type="text" name="username"><input type="password" name="password"></form></html>'
    home_page = b'<html><title>Router Status</title><table><tr><th>Device Name</th><th>IP Address</th><th>MAC Address</th></tr><tr><td>Phone</td><td>192.168.1.20</td><td>aa:bb:cc:dd:ee:ff</td></tr></table><table><tr><th>Domain</th><th>Time</th></tr><tr><td>example.org</td><td>12:00</td></tr></table></html>'
    calls = []

    def fake_open(opener, url, data=None):
        calls.append((url, data))
        if data is None:
            return (login_page, "text/html", "http://192.168.1.1/login.asp"), 200, None
        assert b"username=admin" in data
        assert b"password=not-stored" in data
        assert b"csrf=abc" in data
        return (home_page, "text/html", "http://192.168.1.1/status.asp"), 200, None

    monkeypatch.setattr(router_integration, "_open_page", fake_open)
    result = router_integration.login_router("http://192.168.1.1/login.asp", "admin", "not-stored")
    assert result["authenticated"] is True
    assert len(calls) == 2
    assert "password" not in str(router_integration._SESSIONS[result["session_id"]])


def test_router_snapshot_extracts_device_and_domain_tables(monkeypatch):
    login_page = b'<html><title>Router</title><form method="post"><input name="username"><input type="password" name="password"></form></html>'
    home_page = b'<html><title>Router Status</title><table><tr><th>Device Name</th><th>IP Address</th><th>MAC Address</th></tr><tr><td>Phone</td><td>192.168.1.20</td><td>aa:bb:cc:dd:ee:ff</td></tr></table><table><tr><th>Domain</th><th>Time</th></tr><tr><td>example.org</td><td>12:00</td></tr></table></html>'

    def fake_open(opener, url, data=None):
        if data is None and url.endswith("login.asp"):
            return (login_page, "text/html", url), 200, None
        return (home_page, "text/html", "http://192.168.1.1/status.asp"), 200, None

    monkeypatch.setattr(router_integration, "_open_page", fake_open)
    connected = router_integration.login_router("192.168.1.1/login.asp", "admin", "secret")
    snapshot = router_integration.router_snapshot(connected["session_id"])
    assert snapshot["capabilities"]["device_inventory"] is True
    assert snapshot["capabilities"]["domain_activity"] is True
    assert snapshot["capabilities"]["per_device_traffic"] is False
    assert snapshot["capabilities"]["router_blocking"] is False
    assert snapshot["devices"][0]["rows"][0]["ip address"] == "192.168.1.20"
    assert snapshot["domains"][0]["rows"][0]["domain"] == "example.org"


def test_router_login_rejects_ambiguous_form(monkeypatch):
    page = b'<html><form method="post"><input type="password" name="p1"><input type="password" name="p2"><input name="username"></form></html>'
    monkeypatch.setattr(
        router_integration, "_open_page",
        lambda opener, url, data=None: ((page, "text/html", url), 200, None),
    )
    with pytest.raises(ValueError, match="could not identify"):
        router_integration.login_router("192.168.1.1", "admin", "secret")


def test_router_logout_invalidates_session():
    with router_integration._SESSION_LOCK:
        router_integration._SESSIONS["test-session"] = {
            "last_seen": router_integration.time.monotonic(),
        }
    assert router_integration.logout_router("test-session") is True
    with pytest.raises(ValueError, match="not found"):
        router_integration.router_snapshot("test-session")


def test_router_login_api_does_not_return_credentials(monkeypatch):
    from app import main
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "login_router", lambda address, username, password: {
        "session_id": "temporary-session", "authenticated": True,
        "message": "Credentials were not saved.", "capabilities": [],
    })
    with TestClient(main.app) as client:
        response = client.post("/api/network/router/login", json={
            "address": "192.168.1.1", "username": "admin", "password": "example-secret",
        })
    assert response.status_code == 200
    assert "example-secret" not in response.text
    assert response.json()["authenticated"] is True
