"""Deterministic event detection rules.

Rules inspect normalized event fields only. They never execute commands or content.
"""
from __future__ import annotations

from typing import Any

RULES: tuple[dict[str, str], ...] = (
    {
        "id": "AUTH-001",
        "name": "Repeated authentication failures",
        "description": "Flags an authentication event reporting five or more failed attempts.",
        "severity": "high",
    },
)


def evaluate_event(event: dict[str, Any]) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    event_type = str(event.get("event_type", "")).strip().lower()
    metadata = event.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    if event_type in {"authentication", "authentication_failure", "auth_failure"}:
        attempts = metadata.get("failed_attempts", metadata.get("attempts", 0))
        try:
            count = int(attempts)
        except (TypeError, ValueError):
            count = 0
        if count >= 5:
            rule = RULES[0]
            matches.append({
                "rule_id": rule["id"],
                "title": rule["name"],
                "severity": rule["severity"],
                "description": f"Event reports {count} failed authentication attempts.",
            })
    return matches
