"""Safe discovery of a local router administration login page.

This module deliberately does not submit credentials, follow redirects, or modify router
configuration. Vendor-specific authenticated adapters can be added after capability discovery.
"""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class _LoginPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] = []
        self.in_title = False
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None
        self.password_fields = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        elif tag.lower() == "form":
            self._form = {
                "method": (values.get("method") or "get").lower(),
                "action": values.get("action") or "",
                "field_names": [],
            }
            self.forms.append(self._form)
        elif tag.lower() == "input":
            input_type = (values.get("type") or "text").lower()
            if input_type == "password":
                self.password_fields += 1
            if self._form is not None and input_type not in {"submit", "button", "hidden", "password"}:
                fields = self._form["field_names"]
                if isinstance(fields, list) and values.get("name"):
                    fields.append(str(values["name"])[:80])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
        elif tag.lower() == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self.in_title and len("".join(self.title_parts)) < 200:
            self.title_parts.append(data.strip())


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_router_url(address: str) -> str:
    raw = address.strip()
    if not raw:
        raise ValueError("Enter the router's local administration address.")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP or HTTPS router administration pages are supported.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Do not include credentials, query parameters, or fragments in the router URL.")
    if not parsed.hostname:
        raise ValueError("Enter a valid router IP address.")
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("For safety, enter the router's private IPv4 address, not a hostname.") from exc
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise ValueError("Router address must be a private, non-loopback IPv4 address.")
    if ip.is_reserved:
        raise ValueError("Reserved IP addresses cannot be used as router targets.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Router port is invalid.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Router port is invalid.")
    path = parsed.path or "/"
    return parsed._replace(path=path).geturl()


def inspect_router_login(address: str) -> dict[str, object]:
    """Fetch a bounded login page and report only non-sensitive form metadata."""
    url = _validate_router_url(address)
    request = Request(url, headers={"User-Agent": "SENTINEL-Router-Discovery/0.1", "Accept": "text/html"})
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=4) as response:
            status = response.status
            content_type = response.headers.get("Content-Type", "")
            body = response.read(131073)
    except HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            return {
                "reachable": True, "status": "redirect_not_followed", "http_status": exc.code,
                "final_url": url, "title": "", "login_form_detected": False,
                "capabilities": [], "message": "Router redirected the request. Redirects are not followed for safety; use the final local HTTPS address if available.",
            }
        raise OSError(f"HTTP {exc.code}") from exc
    except URLError as exc:
        raise OSError(str(exc.reason)) from exc
    if len(body) > 131072:
        body = body[:131072]
    if "html" not in content_type.lower() and not body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return {
            "reachable": True, "status": "non_html_response", "http_status": status,
            "final_url": url, "title": "", "login_form_detected": False,
            "capabilities": [], "message": "The router responded, but did not expose an HTML login page at this address.",
        }
    parser = _LoginPageParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()[:160]
    text = body.decode("utf-8", errors="ignore").lower()
    vendor = "unknown"
    if "tp-link" in text or "tplink" in text:
        vendor = "tp-link"
    elif "d-link" in text or "dlink" in text:
        vendor = "d-link"
    elif "netlink" in text:
        vendor = "netlink"
    login_detected = parser.password_fields > 0
    return {
        "reachable": True, "status": "login_page_detected" if login_detected else "page_reached",
        "http_status": status, "final_url": url, "title": title,
        "vendor_hint": vendor, "login_form_detected": login_detected,
        "form_count": len(parser.forms), "password_fields": parser.password_fields,
        "capabilities": [],
        "message": (
            "Login page detected. Authentication and supported monitoring features have not yet been verified."
            if login_detected else
            "Router page reached. No password field was detected on this page."
        ),
        "security_note": "Credentials were not submitted or stored. No router settings were changed.",
    }
