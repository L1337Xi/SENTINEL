"""Safe, ephemeral router login and vendor-neutral administration-page inspection.

Only a private IPv4 address is accepted. Credentials are submitted only to a detected
same-origin HTML POST login form. They are never persisted; authenticated cookies live
in memory for a short session. No router settings are changed by this module.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import threading
import time
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener

MAX_PAGE_BYTES = 512 * 1024
SESSION_TTL_SECONDS = 1800
MAX_DISCOVERY_PAGES = 8
_SESSIONS: dict[str, dict] = {}
_SESSION_LOCK = threading.RLock()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] = []
        self.in_title = False
        self.forms: list[dict] = []
        self.links: list[str] = []
        self.tables: list[list[list[str]]] = []
        self._form: dict | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._table: list[list[str]] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self._form = {
                "method": (values.get("method") or "get").lower(),
                "action": values.get("action") or "",
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({
                "name": values.get("name") or "",
                "type": (values.get("type") or "text").lower(),
                "value": values.get("value") or "",
            })
        elif tag == "a" and values.get("href"):
            self.links.append(str(values["href"])[:512])
        elif tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in {"th", "td"} and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self._form = None
        elif tag in {"th", "td"} and self._cell is not None and self._row is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip()[:300])
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            if self._row:
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            if self._table:
                self.tables.append(self._table)
            self._table = None

    def handle_data(self, data: str) -> None:
        if self.in_title and len("".join(self.title_parts)) < 200:
            self.title_parts.append(data.strip())
        if self._cell is not None:
            self._cell.append(data)


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
        raise ValueError("Enter the router's private IPv4 address, not a hostname.") from exc
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        raise ValueError("Router address must be a private, non-loopback IPv4 address.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Router port is invalid.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Router port is invalid.")
    return parsed._replace(path=parsed.path or "/").geturl()


def _same_origin(base: str, candidate: str) -> bool:
    left, right = urlsplit(base), urlsplit(candidate)
    return (
        left.scheme == right.scheme
        and left.hostname == right.hostname
        and (left.port or (443 if left.scheme == "https" else 80))
        == (right.port or (443 if right.scheme == "https" else 80))
    )


def _open_page(opener, url: str, data: bytes | None = None):
    request = Request(
        url,
        data=data,
        headers={
            "User-Agent": "SENTINEL-Router-Integration/0.2",
            "Accept": "text/html,application/xhtml+xml",
            "Content-Type": "application/x-www-form-urlencoded" if data is not None else "text/html",
        },
    )
    try:
        response = opener.open(request, timeout=5)
    except HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            location = exc.headers.get("Location")
            exc.close()
            return None, exc.code, location
        raise OSError(f"Router returned HTTP {exc.code}.") from exc
    with response:
        content_type = response.headers.get("Content-Type", "")
        body = response.read(MAX_PAGE_BYTES + 1)
        return (body[:MAX_PAGE_BYTES], content_type, response.geturl()), response.status, None


def _parse_page(body: bytes) -> tuple[_PageParser, str]:
    parser = _PageParser()
    text = body.decode("utf-8", errors="replace")
    parser.feed(text)
    title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()[:160]
    return parser, title


def _vendor_hint(body: bytes) -> str:
    text = body.decode("utf-8", errors="ignore").lower()
    if "tp-link" in text or "tplink" in text:
        return "tp-link"
    if "d-link" in text or "dlink" in text:
        return "d-link"
    if "netlink" in text:
        return "netlink"
    return "unknown"


def inspect_router_login(address: str) -> dict:
    """Inspect a private router login page without submitting credentials."""
    url = _validate_router_url(address)
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    page, status, redirect = _open_page(opener, url)
    if redirect:
        return {
            "reachable": True, "status": "redirect_not_followed", "http_status": status,
            "final_url": url, "title": "", "login_form_detected": False,
            "capabilities": [], "message": "Router redirected the request. Enter the final local address directly.",
        }
    body, content_type, final_url = page
    if "html" not in content_type.lower() and not body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return {
            "reachable": True, "status": "non_html_response", "http_status": status,
            "final_url": final_url, "title": "", "login_form_detected": False,
            "capabilities": [], "message": "The router responded, but this address did not return an HTML page.",
        }
    parser, title = _parse_page(body)
    passwords = sum(1 for form in parser.forms for field in form["inputs"] if field["type"] == "password")
    vendor = _vendor_hint(body)
    return {
        "reachable": True, "status": "login_page_detected" if passwords else "page_reached",
        "http_status": status, "final_url": final_url, "title": title,
        "vendor_hint": vendor, "login_form_detected": passwords > 0,
        "form_count": len(parser.forms), "password_fields": passwords,
        "capabilities": [],
        "message": "Login form detected. Authentication is available for standard same-origin HTML POST forms."
        if passwords else "Router page reached. No password field was detected.",
        "security_note": "Credentials are not submitted during discovery.",
    }


def login_router(address: str, username: str, password: str) -> dict:
    """Submit credentials to one unambiguous, same-origin HTML POST login form."""
    url = _validate_router_url(address)
    if not username.strip() or not password:
        raise ValueError("Enter both router username and password.")
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()), _NoRedirect())
    page, _, redirect = _open_page(opener, url)
    if redirect:
        raise ValueError("Router redirected the login page. Enter its final local address directly.")
    body, _, final_url = page
    parser, _ = _parse_page(body)
    candidates = []
    for form in parser.forms:
        fields = form["inputs"]
        passwords = [field for field in fields if field["type"] == "password" and field["name"]]
        users = [
            field for field in fields
            if field["type"] in {"text", "email"} and field["name"]
            and any(word in field["name"].lower() for word in ("user", "login", "account", "name"))
        ]
        if form["method"] == "post" and len(passwords) == 1 and len(users) == 1:
            candidates.append((form, users[0], passwords[0]))
    if len(candidates) != 1:
        raise ValueError(
            "SENTINEL could not identify one standard username/password POST form. "
            "This router may require a vendor-specific JavaScript or challenge-response login."
        )
    form, user_field, password_field = candidates[0]
    action = urljoin(final_url, form["action"] or final_url)
    if not _same_origin(final_url, action):
        raise ValueError("Router login form submits to a different origin; credentials were not sent.")
    values: dict[str, str] = {}
    for field in form["inputs"]:
        if field["type"] == "hidden" and field["name"]:
            values[field["name"]] = field["value"]
    values[user_field["name"]] = username.strip()
    values[password_field["name"]] = password
    response, _, redirect = _open_page(opener, action, urlencode(values).encode())
    if redirect:
        destination = urljoin(action, redirect)
        if not _same_origin(final_url, destination):
            raise ValueError("Router login redirected outside its own origin; session rejected.")
        response, response_status, second_redirect = _open_page(opener, destination)
        if second_redirect:
            raise ValueError("Router login returned multiple redirects; session rejected.")
    result_body, _, result_url = response
    result_parser, result_title = _parse_page(result_body)
    still_login = any(
        field["type"] == "password"
        for form_item in result_parser.forms for field in form_item["inputs"]
    )
    if still_login:
        raise ValueError("Router did not accept the credentials, or requires an unsupported login challenge.")
    session_id = secrets.token_urlsafe(32)
    with _SESSION_LOCK:
        _SESSIONS[session_id] = {
            "opener": opener, "base_url": final_url, "created": time.monotonic(),
            "last_seen": time.monotonic(), "vendor_hint": _vendor_hint(result_body),
            "title": result_title, "last_url": result_url,
        }
    return {
        "session_id": session_id, "authenticated": True,
        "vendor_hint": _vendor_hint(result_body), "title": result_title,
        "expires_in_seconds": SESSION_TTL_SECONDS,
        "message": "Router session established in memory. Credentials were not saved.",
        "transport_warning": "Credentials and session traffic use unencrypted HTTP." if urlsplit(final_url).scheme == "http" else None,
        "capabilities": [],
    }


def _get_session(session_id: str) -> dict:
    with _SESSION_LOCK:
        session = _SESSIONS.get(session_id)
        if session is None:
            raise ValueError("Router session not found. Connect again.")
        if time.monotonic() - session["last_seen"] > SESSION_TTL_SECONDS:
            _SESSIONS.pop(session_id, None)
            raise ValueError("Router session expired. Connect again.")
        session["last_seen"] = time.monotonic()
        return session


def logout_router(session_id: str) -> bool:
    with _SESSION_LOCK:
        return _SESSIONS.pop(session_id, None) is not None


def _normalise_table(table: list[list[str]]) -> tuple[list[str], list[dict[str, str]]] | None:
    if len(table) < 2:
        return None
    headers = [re.sub(r"\s+", " ", item).strip().lower() for item in table[0]]
    if not any(any(key in header for key in ("ip", "mac", "device", "host", "client", "domain", "website", "upload", "download", "rx", "tx")) for header in headers):
        return None
    rows = []
    for values in table[1:101]:
        if len(values) != len(headers):
            continue
        rows.append({headers[index][:60]: values[index] for index in range(len(headers))})
    return (headers, rows) if rows else None


def router_snapshot(session_id: str) -> dict:
    """Read same-origin router pages and extract only structured table data."""
    session = _get_session(session_id)
    base_url = session["base_url"]
    opener = session["opener"]
    queue = [session["last_url"]]
    visited: set[str] = set()
    tables: list[dict] = []
    pages: list[dict] = []
    while queue and len(visited) < MAX_DISCOVERY_PAGES:
        url = queue.pop(0)
        if url in visited or not _same_origin(base_url, url):
            continue
        visited.add(url)
        try:
            page, status, redirect = _open_page(opener, url)
        except (OSError, URLError, TimeoutError):
            continue
        if redirect:
            target = urljoin(url, redirect)
            if _same_origin(base_url, target) and target not in visited:
                queue.append(target)
            continue
        body, content_type, final_url = page
        if "html" not in content_type.lower() and not body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            continue
        parser, title = _parse_page(body)
        pages.append({"title": title, "url": final_url, "http_status": status})
        for table in parser.tables:
            normalised = _normalise_table(table)
            if normalised:
                headers, rows = normalised
                tables.append({"page_title": title, "url": final_url, "headers": headers, "rows": rows})
        for link in parser.links:
            target = urljoin(final_url, link)
            lowered = target.lower()
            if _same_origin(base_url, target) and any(
                term in lowered for term in ("client", "device", "dhcp", "wireless", "traffic", "status", "dns", "access", "network")
            ) and target not in visited and target not in queue:
                queue.append(target)
    device_tables = [
        item for item in tables
        if any(any(key in header for key in ("ip", "mac", "device", "host", "client")) for header in item["headers"])
    ]
    traffic_tables = [
        item for item in tables
        if any(any(key in header for key in ("upload", "download", "rx", "tx", "bytes")) for header in item["headers"])
    ]
    domain_tables = [
        item for item in tables
        if any(any(key in header for key in ("domain", "website", "url", "hostname")) for header in item["headers"])
    ]
    return {
        "authenticated": True, "vendor_hint": session["vendor_hint"],
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pages_inspected": pages, "tables": tables,
        "devices": device_tables, "traffic": traffic_tables, "domains": domain_tables,
        "capabilities": {
            "device_inventory": bool(device_tables),
            "per_device_traffic": bool(traffic_tables),
            "domain_activity": bool(domain_tables),
            "router_blocking": False,
        },
        "limitations": [
            "Router HTML table parsing is best-effort and varies by firmware.",
            "Website history may not be exposed by the router; DNS tables are not proof of full HTTPS browsing history.",
            "Device blocking is not enabled without a verified model-specific access-control adapter.",
        ],
    }
