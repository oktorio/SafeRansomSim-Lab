"""Containment primitives and fixed-boundary safety checks."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from pathlib import Path

from . import config


class SafetyError(RuntimeError):
    """Raised whenever a containment or authorization invariant is violated."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_reparse_point(path: Path) -> bool:
    """Best-effort Windows reparse-point detection; harmless elsewhere."""
    try:
        attrs = path.lstat().st_file_attributes  # type: ignore[attr-defined]
        return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)  # type: ignore[attr-defined]
    except (AttributeError, FileNotFoundError, OSError):
        return False


def reject_link(path: Path) -> None:
    if path.is_symlink() or is_reparse_point(path):
        raise SafetyError(f"Symlink/reparse point rejected: {path}")


def canonical_within(path: Path, root: Path) -> Path:
    canonical_root = root.resolve(strict=False)
    canonical_path = path.resolve(strict=False)
    if canonical_path != canonical_root and canonical_root not in canonical_path.parents:
        raise SafetyError(f"Path escaped safety root: {path}")
    return canonical_path


def reject_link_components(path: Path, root: Path) -> None:
    canonical_within(path, root)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise SafetyError(f"Path is not lexically contained by root: {path}") from exc

    current = root
    if current.exists() or current.is_symlink():
        reject_link(current)
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            reject_link(current)


def ensure_lab_integrity(create: bool = False) -> None:
    lexical_lab = config.BASE_DIR / "ransomware_lab"
    if lexical_lab.exists() or lexical_lab.is_symlink():
        reject_link(lexical_lab)
        canonical_within(lexical_lab, config.BASE_DIR)
    elif create:
        lexical_lab.mkdir(parents=False, exist_ok=False)
    else:
        raise SafetyError("Lab directory does not exist; run --setup first.")

    reject_link(lexical_lab)
    canonical_within(lexical_lab, config.BASE_DIR)
    for root in (
        config.TARGET_ROOT,
        config.BACKUP_ROOT,
        config.LOG_ROOT,
        config.RECOVERY_ROOT,
        config.REPORT_ROOT,
    ):
        canonical_within(root, lexical_lab)
        if root.exists() or root.is_symlink():
            reject_link(root)


def validate_manifest_relative(relative: str) -> Path:
    """Validate manifest paths independent of host path-separator semantics."""
    if not relative or "\x00" in relative:
        raise SafetyError("Invalid empty/NUL manifest path.")
    if relative.startswith(("//", "\\\\")) or re.match(r"^[A-Za-z]:", relative):
        raise SafetyError(f"Network/drive path rejected: {relative!r}")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", relative):
        raise SafetyError(f"URI-style path rejected: {relative!r}")

    normalized = relative.replace("\\", "/")
    if normalized.startswith("/"):
        raise SafetyError(f"Absolute path rejected: {relative!r}")
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SafetyError(f"Traversal/ambiguous path rejected: {relative!r}")
    if len(parts) - 1 > config.MAX_RECURSION_DEPTH:
        raise SafetyError(f"Maximum recursion depth exceeded: {relative!r}")

    rel = Path(*parts)
    if rel.name.endswith(config.LOCKED_SUFFIX) or rel.name == config.RANSOM_NOTE.name:
        raise SafetyError(f"Reserved simulator filename rejected: {relative!r}")
    return rel


def target_path(relative: str) -> Path:
    rel = validate_manifest_relative(relative)
    path = config.TARGET_ROOT / rel
    canonical_within(path, config.TARGET_ROOT)
    reject_link_components(path, config.TARGET_ROOT)
    return path


def backup_path(relative: str) -> Path:
    rel = validate_manifest_relative(relative)
    path = config.BACKUP_ROOT / rel
    canonical_within(path, config.BACKUP_ROOT)
    reject_link_components(path, config.BACKUP_ROOT)
    return path


def locked_path(relative: str) -> Path:
    original = target_path(relative)
    path = original.with_name(original.name + config.LOCKED_SUFFIX)
    canonical_within(path, config.TARGET_ROOT)
    reject_link_components(path, config.TARGET_ROOT)
    return path


def atomic_write(path: Path, data: bytes, root: Path) -> None:
    canonical_within(path, root)
    reject_link_components(path.parent, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_link_components(path.parent, root)
    if path.exists() or path.is_symlink():
        reject_link(path)

    tmp = path.with_name(path.name + f".tmp-{uuid.uuid4().hex}")
    canonical_within(tmp, root)
    reject_link_components(tmp.parent, root)
    with tmp.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def require_authorization() -> None:
    ensure_lab_integrity(create=False)
    canonical_within(config.AUTH_FILE, config.LAB_ROOT)
    if not config.AUTH_FILE.is_file():
        raise SafetyError("Authorization marker missing.")
    reject_link(config.AUTH_FILE)
    if config.AUTH_FILE.read_text(encoding="utf-8").strip() != config.AUTH_PHRASE:
        raise SafetyError("Authorization phrase is invalid.")


def kill_switch_present() -> bool:
    canonical_within(config.STOP_FILE, config.LAB_ROOT)
    if config.STOP_FILE.exists() or config.STOP_FILE.is_symlink():
        reject_link(config.STOP_FILE)
        return True
    return False
