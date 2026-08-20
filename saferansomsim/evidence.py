"""Tamper-evident evidence manifests for fixed SOC/IR exercises."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import config
from .safety import SafetyError, atomic_write, canonical_within, reject_link, reject_link_components, sha256_file
from .telemetry import utc_now

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DETECTION_ROOT = PROJECT_ROOT / "detections"


def _manifest_path(root: Path) -> Path:
    path = root / "evidence-manifest.json"
    canonical_within(path, root)
    return path


def _entry(scope: str, path: Path, base: Path) -> dict[str, Any]:
    canonical_within(path, base)
    if not path.is_file() or path.is_symlink():
        raise SafetyError(f"Evidence file missing or unsafe: {path}")
    return {
        "scope": scope,
        "path": path.relative_to(base).as_posix(),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _detection_entries() -> list[dict[str, Any]]:
    canonical_within(DETECTION_ROOT, PROJECT_ROOT)
    entries: list[dict[str, Any]] = []
    for path in sorted(DETECTION_ROOT.rglob("*")):
        if path.is_symlink():
            raise SafetyError(f"Symlink rejected in Detection Pack: {path}")
        if path.is_file():
            entries.append(_entry("repository", path, PROJECT_ROOT))
    return entries


def _load_owned_manifest(root: Path, scenario_id: str) -> dict[str, Any]:
    path = _manifest_path(root)
    if not path.is_file() or path.is_symlink():
        raise SafetyError("Evidence manifest missing or unsafe.")
    reject_link(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("project") != config.PROJECT_NAME
        or payload.get("scenario_id") != scenario_id
        or payload.get("schema_version") != 1
    ):
        raise SafetyError("Evidence manifest ownership mismatch.")
    return payload


def write_initial_manifest(root: Path, scenario_id: str) -> Path:
    canonical_within(root, config.LAB_ROOT)
    reject_link_components(root, config.LAB_ROOT)
    evidence_files = [
        root / "LAB_NOTICE.txt",
        root / "briefing.md",
        root / "evidence" / "events.jsonl",
    ]
    payload = {
        "schema_version": 1,
        "project": config.PROJECT_NAME,
        "project_version": config.PROJECT_VERSION,
        "scenario_id": scenario_id,
        "generated_at": utc_now(),
        "evidence": [_entry("exercise", path, root) for path in evidence_files] + _detection_entries(),
        "artifacts": [],
    }
    path = _manifest_path(root)
    if path.exists() or path.is_symlink():
        raise SafetyError("Refusing to overwrite existing evidence manifest.")
    atomic_write(path, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(), root)
    return path


def record_artifacts(root: Path, scenario_id: str, paths: list[Path]) -> Path:
    payload = _load_owned_manifest(root, scenario_id)
    payload["project_version"] = config.PROJECT_VERSION
    payload["generated_at"] = utc_now()
    payload["artifacts"] = [_entry("exercise", path, root) for path in paths]
    path = _manifest_path(root)
    atomic_write(path, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(), root)
    return path


def verify_manifest(root: Path, scenario_id: str, include_artifacts: bool = True) -> dict[str, Any]:
    payload = _load_owned_manifest(root, scenario_id)
    errors: list[str] = []
    checked = 0
    groups = [payload.get("evidence", [])]
    if include_artifacts:
        groups.append(payload.get("artifacts", []))
    for entries in groups:
        if not isinstance(entries, list):
            errors.append("malformed manifest entry list")
            continue
        for item in entries:
            if not isinstance(item, dict):
                errors.append("malformed manifest entry")
                continue
            scope = item.get("scope")
            relative = item.get("path")
            if not isinstance(relative, str) or scope not in {"exercise", "repository"}:
                errors.append("invalid manifest path or scope")
                continue
            base = root if scope == "exercise" else PROJECT_ROOT
            path = base / Path(*relative.split("/"))
            try:
                canonical_within(path, base)
                if not path.is_file() or path.is_symlink():
                    errors.append(f"missing_or_unsafe:{scope}:{relative}")
                    continue
                reject_link(path)
                checked += 1
                if sha256_file(path) != item.get("sha256") or path.stat().st_size != item.get("size"):
                    errors.append(f"hash_or_size_mismatch:{scope}:{relative}")
            except (OSError, SafetyError):
                errors.append(f"verification_error:{scope}:{relative}")
    return {"status": "pass" if not errors else "fail", "checked": checked, "errors": errors}
