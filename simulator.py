#!/usr/bin/env python3
"""SafeRansomSim-Lab: constrained ransomware-behavior simulator.

The simulator has no arbitrary target option, no propagation, no persistence,
no network behavior, and no security-tool evasion. It only processes disposable
files created by its own --setup command inside ransomware_lab/test123.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import config


class SafetyError(RuntimeError):
    """Raised whenever a containment or authorization invariant is violated."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    for root in (config.TARGET_ROOT, config.BACKUP_ROOT, config.LOG_ROOT, config.RECOVERY_ROOT):
        canonical_within(root, lexical_lab)
        if root.exists() or root.is_symlink():
            reject_link(root)


def validate_manifest_relative(relative: str) -> Path:
    if not relative or "\x00" in relative:
        raise SafetyError("Invalid empty/NUL manifest path.")
    if relative.startswith(("//", "\\\\")) or re.match(r"^[A-Za-z]:", relative):
        raise SafetyError(f"Network/drive path rejected: {relative!r}")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", relative):
        raise SafetyError(f"URI-style path rejected: {relative!r}")

    rel = Path(relative)
    if rel.is_absolute() or rel.anchor:
        raise SafetyError(f"Absolute path rejected: {relative!r}")
    if any(part in ("", ".", "..") for part in rel.parts):
        raise SafetyError(f"Traversal/ambiguous path rejected: {relative!r}")
    if len(rel.parts) - 1 > config.MAX_RECURSION_DEPTH:
        raise SafetyError(f"Maximum recursion depth exceeded: {relative!r}")
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


def atomic_write(path: Path, data: bytes, root: Path) -> None:
    canonical_within(path, root)
    reject_link_components(path.parent, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_link_components(path.parent, root)
    if path.exists() or path.is_symlink():
        reject_link(path)
    tmp = path.with_name(path.name + f".tmp-{uuid.uuid4().hex}")
    canonical_within(tmp, root)
    with tmp.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def log_event(event: str, session_id: str, **fields: Any) -> None:
    ensure_lab_integrity(create=False)
    reject_link_components(config.LOG_ROOT, config.LAB_ROOT)
    config.LOG_ROOT.mkdir(parents=True, exist_ok=True)
    reject_link(config.LOG_ROOT)
    path = config.LOG_ROOT / "events.jsonl"
    canonical_within(path, config.LOG_ROOT)
    if path.exists() or path.is_symlink():
        reject_link(path)
    record = {"timestamp": utc_now(), "session_id": session_id, "event": event, **fields}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


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


def require_authorization(session_id: str) -> None:
    ensure_lab_integrity(create=False)
    canonical_within(config.AUTH_FILE, config.LAB_ROOT)
    if not config.AUTH_FILE.is_file():
        raise SafetyError("Authorization marker missing.")
    reject_link(config.AUTH_FILE)
    if config.AUTH_FILE.read_text(encoding="utf-8").strip() != config.AUTH_PHRASE:
        raise SafetyError("Authorization phrase is invalid.")
    log_event("AUTHORIZATION_VERIFIED", session_id, safety_validation_result="pass")


def check_kill_switch(session_id: str) -> bool:
    canonical_within(config.STOP_FILE, config.LAB_ROOT)
    if config.STOP_FILE.exists() or config.STOP_FILE.is_symlink():
        reject_link(config.STOP_FILE)
        log_event("SIMULATION_STOPPED", session_id, reason="kill_switch")
        return True
    return False


def validate_inventory(manifest: dict[str, Any]) -> list[tuple[dict[str, Any], Path]]:
    validated: list[tuple[dict[str, Any], Path]] = []
    total_size = 0
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("relative_path"), str):
            raise SafetyError("Malformed manifest entry.")
        path = target_path(entry["relative_path"])
        if not path.is_file():
            raise SafetyError(f"Expected disposable test file missing: {entry['relative_path']}")
        reject_link(path)
        size = path.stat().st_size
        if size > config.MAX_FILE_SIZE:
            raise SafetyError(f"File exceeds 5 MiB limit: {entry['relative_path']}")
        total_size += size
        if total_size > config.MAX_TOTAL_SIZE:
            raise SafetyError("Total data exceeds 100 MiB limit.")
        with path.open("rb") as handle:
            marker = handle.read(len(config.TEST_MARKER))
        if marker != config.TEST_MARKER:
            raise SafetyError(f"Simulator marker missing: {entry['relative_path']}")
        if sha256_file(path) != entry.get("sha256"):
            raise SafetyError(f"Hash mismatch before simulation: {entry['relative_path']}")
        if size != entry.get("size"):
            raise SafetyError(f"Size mismatch before simulation: {entry['relative_path']}")
        validated.append((entry, path))
    return validated


def setup() -> None:
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

    write_manifest({
        "version": 1,
        "created_at": utc_now(),
        "purpose": "SafeRansomSim-Lab disposable-file manifest",
        "files": entries,
    })
    print(f"Created {len(entries)} disposable test files in {config.TARGET_ROOT}")
    print("Authorization was NOT created automatically.")
    print("Copy AUTHORIZED_LAB.example.txt to AUTHORIZED_LAB.txt before --simulate.")


def dry_run() -> None:
    session_id = uuid.uuid4().hex
    inventory = validate_inventory(load_manifest())
    total = sum(path.stat().st_size for _, path in inventory)
    print("DRY RUN - no test-file contents will be modified")
    print(f"Fixed target: {config.TARGET_ROOT}")
    print(f"Eligible files: {len(inventory)} | Total bytes: {total}")
    for entry, path in inventory:
        log_event(
            "FILE_DISCOVERED",
            session_id,
            source_file=entry["relative_path"],
            bytes_processed=path.stat().st_size,
            sha256_before=entry["sha256"],
            safety_validation_result="pass",
        )
        print(f"  WOULD PROCESS  {entry['relative_path']}  sha256={entry['sha256'][:16]}...")


def write_key(key: bytes) -> None:
    reject_link_components(config.RECOVERY_ROOT, config.LAB_ROOT)
    config.RECOVERY_ROOT.mkdir(parents=True, exist_ok=True)
    reject_link(config.RECOVERY_ROOT)
    atomic_write(config.KEY_FILE, config.KEY_LABEL + b"\n" + base64.b64encode(key) + b"\n", config.RECOVERY_ROOT)
    try:
        os.chmod(config.KEY_FILE, 0o600)
    except OSError:
        pass


def read_key() -> bytes:
    canonical_within(config.KEY_FILE, config.RECOVERY_ROOT)
    if not config.KEY_FILE.is_file():
        raise SafetyError("Demo recovery key is missing.")
    reject_link(config.KEY_FILE)
    lines = config.KEY_FILE.read_bytes().splitlines()
    if len(lines) != 2 or lines[0] != config.KEY_LABEL:
        raise SafetyError("Invalid demo recovery-key format.")
    key = base64.b64decode(lines[1], validate=True)
    if len(key) != 32:
        raise SafetyError("Invalid AES-256 demo key length.")
    return key


def ransom_note_bytes() -> bytes:
    return (
        "THIS IS A CYBERSECURITY LAB SIMULATION. NO REAL FILES WERE TARGETED.\n\n"
        "SafeRansomSim-Lab demonstrates constrained file-encryption telemetry and recovery.\n"
        "There are no payment instructions, cryptocurrency addresses, attacker contacts, or Tor links.\n"
    ).encode()


def create_ransom_note(session_id: str) -> None:
    atomic_write(config.RANSOM_NOTE, ransom_note_bytes(), config.TARGET_ROOT)
    log_event("RANSOM_NOTE_CREATED", session_id, destination_file=config.RANSOM_NOTE.name)


def simulate(initial_access: bool = False) -> None:
    session_id = uuid.uuid4().hex
    require_authorization(session_id)
    if initial_access:
        log_event(
            "SIMULATED_EMAIL_ATTACHMENT_EXECUTION",
            session_id,
            detail="Harmless local event only; no email payload or delivery mechanism exists.",
        )

    inventory = validate_inventory(load_manifest())
    if config.KEY_FILE.exists() or config.KEY_FILE.is_symlink():
        reject_link(config.KEY_FILE)
        raise SafetyError("Existing demo recovery key detected; recover/cleanup before another simulation.")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = AESGCM.generate_key(bit_length=256)
    write_key(key)
    aesgcm = AESGCM(key)
    log_event("SIMULATION_STARTED", session_id, eligible_files=len(inventory))

    encrypted_count = 0
    for entry, path in inventory:
        if check_kill_switch(session_id):
            break
        relative = entry["relative_path"]
        started = time.perf_counter()
        before = path.read_bytes()
        log_event(
            "FILE_ENCRYPTION_STARTED",
            session_id,
            source_file=relative,
            sha256_before=entry["sha256"],
            bytes_processed=len(before),
        )

        backup = backup_path(relative)
        if backup.exists() or backup.is_symlink():
            reject_link(backup)
            raise SafetyError(f"Backup already exists; refusing overwrite: {relative}")
        atomic_write(backup, before, config.BACKUP_ROOT)
        if sha256_file(backup) != entry["sha256"]:
            raise SafetyError(f"Backup verification failed: {relative}")

        nonce = secrets.token_bytes(12)
        aad = ("SafeRansomSim-Lab:" + relative).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, before, aad)
        locked = path.with_name(path.name + config.LOCKED_SUFFIX)
        canonical_within(locked, config.TARGET_ROOT)
        reject_link_components(locked, config.TARGET_ROOT)
        if locked.exists() or locked.is_symlink():
            reject_link(locked)
            raise SafetyError(f"Locked output already exists: {relative}")
        atomic_write(locked, config.ENCRYPTED_MAGIC + nonce + ciphertext, config.TARGET_ROOT)
        encrypted_hash = sha256_file(locked)
        path.unlink()
        encrypted_count += 1
        log_event(
            "FILE_ENCRYPTION_COMPLETED",
            session_id,
            source_file=relative,
            destination_file=relative + config.LOCKED_SUFFIX,
            sha256_before=entry["sha256"],
            sha256_after=encrypted_hash,
            bytes_processed=len(before),
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            success=True,
            safety_validation_result="pass",
        )

    if encrypted_count:
        create_ransom_note(session_id)
    print(f"Controlled simulation completed: {encrypted_count} disposable file(s) encrypted.")
    print(f"Recovery key: {config.KEY_FILE}")


def _decrypt_locked_blob(blob: bytes, relative: str, key: bytes) -> bytes:
    if len(blob) < len(config.ENCRYPTED_MAGIC) + 12 or not blob.startswith(config.ENCRYPTED_MAGIC):
        raise SafetyError("Invalid locked-file format.")
    nonce_start = len(config.ENCRYPTED_MAGIC)
    nonce = blob[nonce_start:nonce_start + 12]
    ciphertext = blob[nonce_start + 12:]
    aad = ("SafeRansomSim-Lab:" + relative).encode("utf-8")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def _locked_file_is_simulator_owned(path: Path, relative: str, expected_sha256: str, key: bytes | None) -> bool:
    if key is None or not path.is_file():
        return False
    try:
        reject_link(path)
        plaintext = _decrypt_locked_blob(path.read_bytes(), relative, key)
    except Exception:
        return False
    return plaintext.startswith(config.TEST_MARKER) and sha256_bytes(plaintext) == expected_sha256


def recover() -> None:
    session_id = uuid.uuid4().hex
    require_authorization(session_id)
    manifest = load_manifest()
    key = read_key()
    log_event("RECOVERY_STARTED", session_id, manifest_files=len(manifest["files"]))
    recovered = 0
    matched = 0
    failed = 0

    for entry in manifest["files"]:
        relative = entry["relative_path"]
        original = target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        canonical_within(locked, config.TARGET_ROOT)
        reject_link_components(locked, config.TARGET_ROOT)

        if original.exists() or original.is_symlink():
            reject_link(original)
            if original.is_file() and sha256_file(original) == entry["sha256"]:
                matched += 1
                continue
            failed += 1
            log_event(
                "HASH_VERIFICATION_FAILURE",
                session_id,
                source_file=relative,
                reason="original_path_conflict_refusing_overwrite",
            )
            continue

        if not locked.is_file():
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason="locked_file_missing")
            continue
        reject_link(locked)
        try:
            plaintext = _decrypt_locked_blob(locked.read_bytes(), relative, key)
        except Exception as exc:
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason=type(exc).__name__)
            continue

        if not plaintext.startswith(config.TEST_MARKER) or sha256_bytes(plaintext) != entry["sha256"]:
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason="plaintext_manifest_mismatch")
            continue

        atomic_write(original, plaintext, config.TARGET_ROOT)
        recovered += 1
        matched += 1
        locked.unlink()
        log_event("FILE_RECOVERED", session_id, source_file=relative + config.LOCKED_SUFFIX, destination_file=relative)
        log_event("HASH_VERIFICATION_SUCCESS", session_id, source_file=relative, sha256_after=entry["sha256"])

    if failed == 0 and matched == len(manifest["files"]) and config.RANSOM_NOTE.exists():
        reject_link(config.RANSOM_NOTE)
        if config.RANSOM_NOTE.is_file() and config.RANSOM_NOTE.read_bytes() == ransom_note_bytes():
            config.RANSOM_NOTE.unlink()

    print("Recovery verification")
    print(f"Files in manifest : {len(manifest['files'])}")
    print(f"Files recovered   : {recovered}")
    print(f"Hash matched      : {matched}")
    print(f"Hash failed       : {failed}")
    print("RESULT: FULL RECOVERY SUCCESSFUL" if failed == 0 and matched == len(manifest["files"]) else "RESULT: RECOVERY INCOMPLETE")


def status() -> None:
    try:
        ensure_lab_integrity(create=False)
    except SafetyError as exc:
        print(f"Lab status: not initialized ({exc})")
        return
    manifest_exists = config.MANIFEST_FILE.is_file()
    manifest_files = originals = locked_count = 0
    if manifest_exists:
        try:
            manifest = load_manifest()
            manifest_files = len(manifest["files"])
            for entry in manifest["files"]:
                original = target_path(entry["relative_path"])
                originals += int(original.is_file())
                locked = original.with_name(original.name + config.LOCKED_SUFFIX)
                canonical_within(locked, config.TARGET_ROOT)
                if locked.exists() or locked.is_symlink():
                    reject_link(locked)
                locked_count += int(locked.is_file())
        except SafetyError as exc:
            print(f"Manifest safety error: {exc}")
    print(f"Lab root          : {config.LAB_ROOT}")
    print(f"Fixed target      : {config.TARGET_ROOT}")
    print(f"Manifest present  : {manifest_exists}")
    print(f"Manifest files    : {manifest_files}")
    print(f"Original files    : {originals}")
    print(f"Locked files      : {locked_count}")
    print(f"Recovery key      : {config.KEY_FILE.is_file()}")
    print(f"Kill switch       : {config.STOP_FILE.exists()}")
    print(f"Authorization     : {config.AUTH_FILE.is_file()}")


def _delete_if_exact_file(path: Path, root: Path, expected: bytes) -> bool:
    canonical_within(path, root)
    reject_link_components(path, root)
    if not path.exists() and not path.is_symlink():
        return True
    reject_link(path)
    if not path.is_file() or path.read_bytes() != expected:
        return False
    path.unlink()
    return True


def _delete_if_hash(path: Path, root: Path, expected_sha256: str) -> bool:
    canonical_within(path, root)
    reject_link_components(path, root)
    if not path.exists() and not path.is_symlink():
        return True
    reject_link(path)
    if not path.is_file() or sha256_file(path) != expected_sha256:
        return False
    path.unlink()
    return True


def _prune_manifest_parents(paths: list[Path], root: Path) -> None:
    parents: set[Path] = set()
    for path in paths:
        parent = path.parent
        while parent != root and root in parent.parents:
            parents.add(parent)
            parent = parent.parent
    for parent in sorted(parents, key=lambda p: len(p.parts), reverse=True):
        if parent.exists() and not parent.is_symlink():
            reject_link(parent)
            try:
                parent.rmdir()
            except OSError:
                pass


def _events_log_is_simulator_owned(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict) or "event" not in record or "session_id" not in record:
                return False
        return True
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False


def _record_unknown_runtime_files(root: Path, conflicts: list[str]) -> None:
    if not root.exists():
        return
    reject_link(root)
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        canonical_within(current_path, root)
        safe_dirs: list[str] = []
        for name in dirs:
            child = current_path / name
            if child.is_symlink() or is_reparse_point(child):
                conflicts.append(f"preserved symlink/reparse point: {child.relative_to(config.LAB_ROOT)}")
            else:
                safe_dirs.append(name)
        dirs[:] = safe_dirs
        for name in files:
            child = current_path / name
            conflicts.append(f"preserved unknown runtime file: {child.relative_to(config.LAB_ROOT)}")


def cleanup() -> None:
    session_id = uuid.uuid4().hex
    require_authorization(session_id)
    manifest = load_manifest()
    conflicts: list[str] = []
    target_paths: list[Path] = []
    backup_paths: list[Path] = []

    cleanup_key: bytes | None = None
    if config.KEY_FILE.exists() or config.KEY_FILE.is_symlink():
        try:
            cleanup_key = read_key()
        except (SafetyError, ValueError):
            conflicts.append("preserved unknown/conflicting recovery key")

    for entry in manifest["files"]:
        relative = entry["relative_path"]
        original = target_path(relative)
        target_paths.append(original)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        canonical_within(locked, config.TARGET_ROOT)
        reject_link_components(locked, config.TARGET_ROOT)

        if original.exists() or original.is_symlink():
            reject_link(original)
            owned_original = False
            if original.is_file():
                with original.open("rb") as handle:
                    marker = handle.read(len(config.TEST_MARKER))
                owned_original = marker == config.TEST_MARKER and sha256_file(original) == entry["sha256"]
            if owned_original:
                original.unlink()
            else:
                conflicts.append(f"preserved unknown/conflicting file: {relative}")

        if locked.exists() or locked.is_symlink():
            reject_link(locked)
            if _locked_file_is_simulator_owned(locked, relative, entry["sha256"], cleanup_key):
                locked.unlink()
            else:
                conflicts.append(f"preserved unverified/conflicting locked path: {relative + config.LOCKED_SUFFIX}")

        backup = backup_path(relative)
        backup_paths.append(backup)
        if not _delete_if_hash(backup, config.BACKUP_ROOT, entry["sha256"]):
            conflicts.append(f"preserved unknown/conflicting backup: {relative}")

    if not _delete_if_exact_file(config.RANSOM_NOTE, config.TARGET_ROOT, ransom_note_bytes()):
        conflicts.append(f"preserved unknown/conflicting note: {config.RANSOM_NOTE.name}")

    events = config.LOG_ROOT / "events.jsonl"
    canonical_within(events, config.LOG_ROOT)
    if events.exists() or events.is_symlink():
        reject_link(events)
        if _events_log_is_simulator_owned(events):
            events.unlink()
        else:
            conflicts.append("preserved unknown/conflicting events log")

    _prune_manifest_parents(target_paths, config.TARGET_ROOT)
    _prune_manifest_parents(backup_paths, config.BACKUP_ROOT)

    # Any files remaining under runtime roots are not proven simulator-owned.
    for root in (config.TARGET_ROOT, config.BACKUP_ROOT, config.LOG_ROOT):
        _record_unknown_runtime_files(root, conflicts)

    if conflicts:
        print("Cleanup preserved one or more non-owned/conflicting artifacts:")
        for item in sorted(set(conflicts)):
            print(f"  - {item}")
        print("Manifest and recovery key were preserved so the lab state can be reviewed safely.")
        return

    if cleanup_key is not None and config.KEY_FILE.exists():
        reject_link(config.KEY_FILE)
        config.KEY_FILE.unlink()

    for root in (config.TARGET_ROOT, config.BACKUP_ROOT, config.LOG_ROOT, config.RECOVERY_ROOT):
        canonical_within(root, config.LAB_ROOT)
        if root.exists() and not root.is_symlink():
            reject_link(root)
            try:
                root.rmdir()
            except OSError:
                pass

    reject_link(config.MANIFEST_FILE)
    config.MANIFEST_FILE.unlink()
    print("Removed only cryptographically or hash-verified simulator-owned runtime artifacts. Authorization and kill-switch files were preserved.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe, fixed-sandbox ransomware behavior simulator")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--setup", action="store_true", help="create disposable lab files")
    modes.add_argument("--dry-run", action="store_true", help="show eligible files without modifying test files")
    modes.add_argument("--simulate", action="store_true", help="run controlled fixed-sandbox encryption simulation")
    modes.add_argument("--recover", action="store_true", help="decrypt and SHA-256 verify disposable lab files")
    modes.add_argument("--status", action="store_true", help="show current lab state")
    modes.add_argument("--cleanup", action="store_true", help="remove only verified simulator-owned runtime artifacts")
    modes.add_argument(
        "--simulate-initial-access",
        action="store_true",
        help="record a harmless simulated email-execution event, then run the same sandbox simulation",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.setup:
            setup()
        elif args.simulate:
            simulate()
        elif args.recover:
            recover()
        elif args.status:
            status()
        elif args.cleanup:
            cleanup()
        elif args.simulate_initial_access:
            simulate(initial_access=True)
        else:
            dry_run()
        return 0
    except (SafetyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SAFETY ABORT: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
