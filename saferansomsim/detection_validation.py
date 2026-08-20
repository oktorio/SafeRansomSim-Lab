"""Validation for the defensive Detection Pack."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

import yaml

from . import config

REQUIRED_SIGMA_FIELDS = {
    "title", "id", "status", "description", "logsource", "detection", "level"
}


def _repo_detection_root() -> Path:
    return Path(__file__).resolve().parents[1] / "detections"


def validate_detection_pack() -> dict[str, Any]:
    root = _repo_detection_root()
    errors: list[str] = []
    sigma_files = sorted((root / "sigma").glob("*.yml"))
    if not sigma_files:
        errors.append("No Sigma rules found.")

    seen_ids: set[str] = set()
    for path in sigma_files:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{path.name}: YAML parse failed: {type(exc).__name__}")
            continue
        if not isinstance(document, dict):
            errors.append(f"{path.name}: top-level YAML must be a mapping")
            continue
        missing = sorted(REQUIRED_SIGMA_FIELDS - set(document))
        if missing:
            errors.append(f"{path.name}: missing fields: {', '.join(missing)}")
        rule_id = str(document.get("id", ""))
        try:
            uuid.UUID(rule_id)
        except ValueError:
            errors.append(f"{path.name}: invalid UUID id")
        if rule_id in seen_ids:
            errors.append(f"{path.name}: duplicate Sigma id {rule_id}")
        seen_ids.add(rule_id)

        detection = document.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            errors.append(f"{path.name}: detection.condition is required")
        tags = document.get("tags", [])
        if not isinstance(tags, list) or not any(str(tag).startswith("attack.") for tag in tags):
            errors.append(f"{path.name}: at least one attack.* tag is required")

    markdown_files = sorted((root / "siem").glob("*.md")) + sorted((root / "sysmon").glob("*.md"))
    if not markdown_files:
        errors.append("No SIEM/Sysmon detection guidance found.")
    for path in markdown_files:
        text = path.read_text(encoding="utf-8")
        if len(text.strip()) < 80:
            errors.append(f"{path.name}: guidance is unexpectedly short")
        if path.parent.name == "siem" and "```" not in text:
            errors.append(f"{path.name}: SIEM guidance must include a fenced query example")
        if re.search(r"https?://(?!github\.com|attack\.mitre\.org)", text, re.IGNORECASE):
            errors.append(f"{path.name}: unexpected external URL in detection guidance")

    return {
        "valid": not errors,
        "sigma_rules": len(sigma_files),
        "guidance_files": len(markdown_files),
        "errors": errors,
    }


def assert_detection_pack_valid() -> dict[str, Any]:
    result = validate_detection_pack()
    if not result["valid"]:
        raise ValueError("Detection Pack validation failed: " + "; ".join(result["errors"]))
    return result
