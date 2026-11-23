from urllib.error import HTTPError
from io import BytesIO

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
        headers = {"Content-Type": "text/html"}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self, limit):
            return b'<html><head><title>TP-Link Login</title></head><body><form><input name="user"><input type="password" name="pass"></form></body></html>'

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

    monkeypatch.setattr(router_integration, "build_opener", lambda handler: Opener())
    result = router_integration.inspect_router_login("http://192.168.1.1/")
    assert result["status"] == "redirect_not_followed"
    assert result["capabilities"] == []



def test_router_probe_api_returns_discovery_result(monkeypatch):
    from fastapi.testclient import TestClient
    from app import main

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
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        response = client.post("/api/network/router/probe", json={"address": "https://example.com"})
    assert response.status_code == 422
