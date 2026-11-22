"""Edition metadata and capability catalogue for SENTINEL.

Edition selection is a local deployment setting, not a licensing or entitlement
mechanism. Commercial entitlement verification is intentionally not implemented.
"""
from __future__ import annotations

import os
from typing import Any

NORMAL = "normal"
ADVANCED = "advanced"

_FEATURES: tuple[dict[str, Any], ...] = (
    {"id": "host_assessment", "name": "Host assessment", "tier": NORMAL, "status": "available", "description": "Bounded, read-only host inventory and security checks."},
    {"id": "local_hash_intelligence", "name": "Local hash intelligence", "tier": NORMAL, "status": "available", "description": "Operator-supplied SHA-256 indicators."},
    {"id": "malwarebazaar_feed", "name": "MalwareBazaar feed", "tier": NORMAL, "status": "available", "description": "Optional recent-feed matching when locally configured."},
    {"id": "clamav_integration", "name": "ClamAV integration", "tier": NORMAL, "status": "available", "description": "Uses an existing local ClamAV installation and signatures."},
    {"id": "network_discovery", "name": "Scoped network discovery", "tier": NORMAL, "status": "available", "description": "Discovery limited to an attached private IPv4 network."},
    {"id": "events_alerts_cases", "name": "Events, alerts and cases", "tier": NORMAL, "status": "available", "description": "Local event intake, initial detections, alert lifecycle and case workflow."},
    {"id": "software_vulnerability_intel", "name": "Software vulnerability intelligence", "tier": NORMAL, "status": "planned", "description": "Installed-package inventory, advisories, fixed versions and end-of-life checks."},
    {"id": "process_memory_inspection", "name": "Process and executable-memory inspection", "tier": NORMAL, "status": "available", "description": "Bounded read-only process metadata, executable mappings, deleted executables, memfd indicators and process-associated network metadata; no memory contents or command lines are collected."},
    {"id": "continuous_monitoring", "name": "Continuous monitoring", "tier": ADVANCED, "status": "planned", "description": "Ongoing endpoint telemetry and detection."},
    {"id": "advanced_fileless_detection", "name": "Advanced fileless detection", "tier": ADVANCED, "status": "planned", "description": "Correlated process, memory, execution and network indicators."},
    {"id": "behaviour_detection", "name": "Behaviour-based detection", "tier": ADVANCED, "status": "planned", "description": "Correlated activity detections with explainable evidence."},
    {"id": "sandbox_analysis", "name": "Sandbox analysis", "tier": ADVANCED, "status": "planned", "description": "Isolated detonation workflow with explicit safety boundaries."},
    {"id": "ransomware_protection", "name": "Ransomware protection", "tier": ADVANCED, "status": "planned", "description": "Activity detection and recoverability controls; no unsupported rollback promises."},
    {"id": "multi_device_management", "name": "Multi-device management", "tier": ADVANCED, "status": "planned", "description": "Authenticated central management for enrolled endpoints."},
    {"id": "enterprise_reporting", "name": "Advanced reporting", "tier": ADVANCED, "status": "planned", "description": "Extended incident timelines, evidence exports and fleet reporting."},
)


def current_edition() -> str:
    """Return the configured edition, defaulting safely to Normal."""
    requested = os.getenv("SENTINEL_EDITION", NORMAL).strip().lower()
    return requested if requested in {NORMAL, ADVANCED} else NORMAL


def edition_manifest() -> dict[str, Any]:
    """Return public edition metadata without exposing secrets or claiming entitlements."""
    edition = current_edition()
    visible = [
        {**feature, "included": feature["tier"] == NORMAL or edition == ADVANCED}
        for feature in _FEATURES
    ]
    return {
        "edition": edition,
        "display_name": "SENTINEL Advanced" if edition == ADVANCED else "SENTINEL Normal",
        "features": visible,
        "license_enforcement": "not_implemented",
        "notice": (
            "Edition selection is a local configuration setting only. It does not verify "
            "a commercial licence or unlock implemented premium functionality."
        ),
    }
