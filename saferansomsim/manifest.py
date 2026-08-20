"""Disposable-file setup, manifest IO, and eligibility validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import config
from .safety import (
    SafetyError,
    atomic_write,
    canonical_within,
    ensure_lab_integrity,
    reject_link,
    reject_link_components,
    sha256_bytes,
    sha256_file,
    target_path,
)
from .telemetry import utc_now


def write_manifest(manifest: dict[str, Any]) -> None:
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    atomic_write(config.MANIFEST_FILE, payload, config.LAB_ROOT)


def load_manifest() -> dict[str, Any]:
    ensure_lab_integrity(create=False)
    canonical_within(config.MANIFEST_FILE, config.LAB_ROOT)
    if not config.MANIFEST_FILE.is_file():
        raise SafetyError("Manifest missing; run --setup first.")
    reject_link(config.MANIFEST_FILE)
    manifest = json.loads(config.MANIFEST_FILE.read_text(encoding="utf-8"))
    if manifest.get("version") != 1 or not isinstance(manifest.get("files"), list):
        raise SafetyError("Unsupported or malformed manifest.")
    if len(manifest["files"]) > config.MAX_FILES:
        raise SafetyError("Manifest exceeds maximum file count.")
    return manifest


def validate_inventory(manifest: dict[str, Any]) -> list[tuple[dict[str, Any], Path]]:
    validated: list[tuple[dict[str, Any], Path]] = []
    total_size = 0
    seen: set[str] = set()

    for entry in manifest["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("relative_path"), str):
            raise SafetyError("Malformed manifest entry.")
        relative = entry["relative_path"]
        if relative in seen:
            raise SafetyError(f"Duplicate manifest path: {relative}")
        seen.add(relative)

        path = target_path(relative)
        if not path.is_file():
            raise SafetyError(f"Expected disposable test file missing: {relative}")
        reject_link(path)
        size = path.stat().st_size
        if size > config.MAX_FILE_SIZE:
            raise SafetyError(f"File exceeds 5 MiB limit: {relative}")
        total_size += size
        if total_size > config.MAX_TOTAL_SIZE:
            raise SafetyError("Total data exceeds 100 MiB limit.")

        with path.open("rb") as handle:
            marker = handle.read(len(config.TEST_MARKER))
        if marker != config.TEST_MARKER:
            raise SafetyError(f"Simulator marker missing: {relative}")
        if sha256_file(path) != entry.get("sha256"):
            raise SafetyError(f"Hash mismatch before simulation: {relative}")
        if size != entry.get("size"):
            raise SafetyError(f"Size mismatch before simulation: {relative}")
        validated.append((entry, path))
    return validated


def setup() -> dict[str, Any]:
    ensure_lab_integrity(create=True)
    if config.MANIFEST_FILE.exists():
        raise SafetyError("Manifest already exists. Use --status or --cleanup before a new setup.")

    if config.TARGET_ROOT.exists():
        reject_link(config.TARGET_ROOT)
        if any(config.TARGET_ROOT.iterdir()):
            raise SafetyError("test123 is not empty; refusing to touch pre-existing files.")
    else:
        reject_link_components(config.TARGET_ROOT.parent, config.LAB_ROOT)
        config.TARGET_ROOT.mkdir(parents=False)

    samples: dict[str, bytes] = {
        "sample1.txt": config.TEST_MARKER + b"Disposable ransomware-lab sample 1.\n",
        "sample2.txt": config.TEST_MARKER + b"Disposable ransomware-lab sample 2.\n",
        "report-demo.txt": config.TEST_MARKER + b"Quarterly demo report - synthetic data only.\n",
        "image-demo.bin": config.TEST_MARKER + bytes(range(256)) * 4,
        "nested/test-document.txt": config.TEST_MARKER + b"Nested disposable test document.\n",
    }
    entries: list[dict[str, Any]] = []
    for relative, data in samples.items():
        path = target_path(relative)
        if path.exists() or path.is_symlink():
            raise SafetyError(f"Refusing to overwrite existing path: {relative}")
        atomic_write(path, data, config.TARGET_ROOT)
        entries.append({"relative_path": relative, "sha256": sha256_bytes(data), "size": len(data)})

    manifest = {
        "version": 1,
        "created_at": utc_now(),
        "purpose": "SafeRansomSim-Lab disposable-file manifest",
        "files": entries,
    }
    write_manifest(manifest)
    return manifest
