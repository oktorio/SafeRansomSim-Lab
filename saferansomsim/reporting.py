"""Local JSON and standalone HTML reports for lab evidence."""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from . import config
from .safety import SafetyError, atomic_write, canonical_within, ensure_lab_integrity, reject_link, reject_link_components
from .telemetry import events_for_session, utc_now


def _safe_session_id(session_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", session_id):
        raise SafetyError("Invalid report session id.")
    return session_id


def _report_paths(session_id: str) -> tuple[Path, Path]:
    session = _safe_session_id(session_id)
    json_path = config.REPORT_ROOT / f"run-{session}.json"
    html_path = config.REPORT_ROOT / f"run-{session}.html"
    canonical_within(json_path, config.REPORT_ROOT)
    canonical_within(html_path, config.REPORT_ROOT)
    return json_path, html_path


def build_report(session_id: str, operation: str, summary: dict[str, Any]) -> dict[str, Any]:
    events = events_for_session(session_id)
    event_counts = Counter(str(event.get("event", "UNKNOWN")) for event in events)
    return {
        "schema_version": config.REPORT_SCHEMA_VERSION,
        "project": config.PROJECT_NAME,
        "project_version": config.PROJECT_VERSION,
        "generated_at": utc_now(),
        "session_id": session_id,
        "operation": operation,
        "safety_boundary": {
            "fixed_target": str(config.TARGET_ROOT),
            "arbitrary_target_supported": False,
            "network_activity": "none_by_design",
            "privilege_escalation": "not_implemented",
            "persistence": "not_implemented",
            "propagation": "not_implemented",
            "security_tool_evasion": "not_implemented",
        },
        "summary": summary,
        "telemetry": {
            "event_count": len(events),
            "event_types": dict(sorted(event_counts.items())),
        },
    }


def _html_report(report: dict[str, Any]) -> bytes:
    summary = report["summary"]
    boundary = report["safety_boundary"]
    rows = [f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in summary.items()]
    safety_rows = [f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in boundary.items()]
    event_rows = [f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in report["telemetry"]["event_types"].items()]
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{config.PROJECT_NAME} report {html.escape(report['session_id'])}</title>
<style>body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }} table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }} th, td {{ border: 1px solid #bbb; padding: .5rem; text-align: left; vertical-align: top; }} th {{ width: 38%; }} code {{ word-break: break-all; }} .notice {{ border: 1px solid #888; padding: 1rem; margin: 1rem 0 2rem; }}</style>
</head><body>
<h1>{config.PROJECT_NAME} — {html.escape(str(report['operation']))}</h1>
<div class="notice"><strong>Controlled lab evidence.</strong> This report describes only the fixed disposable sandbox. It is not evidence of real ransomware execution.</div>
<p><strong>Version:</strong> {html.escape(config.PROJECT_VERSION)}<br><strong>Session:</strong> <code>{html.escape(report['session_id'])}</code><br><strong>Generated:</strong> {html.escape(report['generated_at'])}</p>
<h2>Run summary</h2><table>{''.join(rows) or '<tr><td>No summary values</td></tr>'}</table>
<h2>Safety boundary</h2><table>{''.join(safety_rows)}</table>
<h2>Telemetry events</h2><table>{''.join(event_rows) or '<tr><td>No events recorded</td></tr>'}</table>
</body></html>"""
    return document.encode("utf-8")


def write_report(session_id: str, operation: str, summary: dict[str, Any]) -> tuple[Path, Path]:
    ensure_lab_integrity(create=False)
    reject_link_components(config.REPORT_ROOT, config.LAB_ROOT)
    config.REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    reject_link(config.REPORT_ROOT)
    json_path, html_path = _report_paths(session_id)
    report = build_report(session_id, operation, summary)
    atomic_write(json_path, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(), config.REPORT_ROOT)
    atomic_write(html_path, _html_report(report), config.REPORT_ROOT)
    return json_path, html_path
