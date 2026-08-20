"""Structured, local-only telemetry for defensive exercises."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .safety import canonical_within, ensure_lab_integrity, reject_link, reject_link_components

KNOWN_EVENTS = {
    "SETUP_COMPLETED",
    "DRY_RUN_STARTED",
    "DRY_RUN_COMPLETED",
    "SIMULATION_STARTED",
    "AUTHORIZATION_VERIFIED",
    "FILE_DISCOVERED",
    "FILE_ENCRYPTION_STARTED",
    "FILE_ENCRYPTION_COMPLETED",
    "RANSOM_NOTE_CREATED",
    "RECOVERY_STARTED",
    "FILE_RECOVERED",
    "HASH_VERIFICATION_SUCCESS",
    "HASH_VERIFICATION_FAILURE",
    "SIMULATION_STOPPED",
    "SIMULATION_COMPLETED",
    "RECOVERY_COMPLETED",
    "CLEANUP_STARTED",
    "CLEANUP_COMPLETED",
    "SIMULATED_EMAIL_ATTACHMENT_EXECUTION",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(event: str, session_id: str, **fields: Any) -> dict[str, Any]:
    if event not in KNOWN_EVENTS:
        raise ValueError(f"Unknown telemetry event: {event}")

    ensure_lab_integrity(create=False)
    reject_link_components(config.LOG_ROOT, config.LAB_ROOT)
    config.LOG_ROOT.mkdir(parents=True, exist_ok=True)
    reject_link(config.LOG_ROOT)

    path = config.EVENT_LOG
    canonical_within(path, config.LOG_ROOT)
    if path.exists() or path.is_symlink():
        reject_link(path)

    record = {
        "schema_version": config.TELEMETRY_SCHEMA_VERSION,
        "project": config.PROJECT_NAME,
        "project_version": config.PROJECT_VERSION,
        "timestamp": utc_now(),
        "session_id": session_id,
        "event": event,
        **fields,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def events_for_session(session_id: str) -> list[dict[str, Any]]:
    path = config.EVENT_LOG
    if not path.is_file():
        return []
    reject_link(path)
    result: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("session_id") == session_id:
            result.append(record)
    return result


def events_log_is_simulator_owned(path: Path) -> bool:
    """Strict enough for deletion, while recognizing v0.1 legacy records."""
    if not path.is_file():
        return False
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                return False
            if record.get("event") not in KNOWN_EVENTS or not isinstance(record.get("session_id"), str):
                return False
            if "project" in record and record.get("project") != config.PROJECT_NAME:
                return False
            if "schema_version" in record and record.get("schema_version") != config.TELEMETRY_SCHEMA_VERSION:
                return False
        return True
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
