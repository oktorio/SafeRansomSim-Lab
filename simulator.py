#!/usr/bin/env python3
"""SafeRansomSim-Lab: constrained ransomware-behavior simulator.

This program has no arbitrary target option, no network behavior, no
persistence, and no propagation. It only processes disposable files created by
its own --setup command inside ransomware_lab/test123.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
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
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
    """Return canonical path only when it is contained by canonical root."""
    canonical_root = root.resolve(strict=False)
    canonical_path = path.resolve(strict=False)
    if canonical_path != canonical_root and canonical_root not in canonical_path.parents:
        raise SafetyError(f"Path escaped safety root: {path}")
    return canonical_path


def ensure_lab_integrity(create: bool = False) -> None:
    """Ensure the lexical lab directory has not been redirected elsewhere."""
    lexical_lab = config.BASE_DIR / "ransomware_lab"
    if lexical_lab.exists() or lexical_lab.is_symlink():
        reject_link(lexical_lab)
        canonical_within(lexical_lab, config.BASE_DIR)
    elif create:
        lexical_lab.mkdir(parents=False, exist_ok=False)
    else:
        raise SafetyError("Lab directory does not exist; run --setup first.")

    # Re-check after creation.
    reject_link(lexical_lab)
    canonical_within(lexical_lab, config.BASE_DIR)

    for root in (config.TARGET_ROOT, config.BACKUP_ROOT, config.LOG_ROOT, config.RECOVERY_ROOT):
        canonical_within(root, lexical_lab)
        if root.exists() or root.is_symlink():
            reject_link(root)


def validate_manifest_relative(relative: str) -> Path:
    """Validate a manifest path without accepting arbitrary filesystem paths."""
    if not relative or "\x00" in relative:
        raise SafetyError("Invalid empty/NUL manifest path.")
    if relative.startswith(("//", "\\\\")) or re.match(r"^[A-Za-z]:", relative):
        raise SafetyError(f"Network/drive path rejected: {relative!r}")

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

    current = config.TARGET_ROOT
    if current.exists() or current.is_symlink():
        reject_link(current)
    for part in rel.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            reject_link(current)
    return path


def backup_path(relative: str) -> Path:
    rel = validate_manifest_relative(relative)
    path = config.BACKUP_ROOT / rel
    canonical_within(path, config.BACKUP_ROOT)
    return path


def atomic_write(path: Path, data: bytes, root: Path) -> None:
    canonical_within(path, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    canonical_within(path.parent, root)
    reject_link(path.parent)
    tmp = path.with_name(path.name + f".tmp-{uuid.uuid4().hex}")
    canonical_within(tmp, root)
    with tmp.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def log_event(event: str, session_id: str, **fields: Any) -> None:
    ensure_lab_integrity(create=False)
    config.LOG_ROOT.mkdir(parents=True, exist_ok=True)
    reject_link(config.LOG_ROOT)
    path = config.LOG_ROOT / "events.jsonl"
    canonical_within(path, config.LOG_ROOT)
    record = {
        "timestamp": utc_now(),
        "session_id": session_id,
        "event": event,
        **fields,
    }
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
    phrase = config.AUTH_FILE.read_text(encoding="utf-8").strip()
    if phrase != config.AUTH_PHRASE:
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
            prefix = handle.read(len(config.TEST_MARKER))
        if prefix != config.TEST_MARKER:
            raise SafetyError(f"Simulator marker missing: {entry['relative_path']}")
        digest = sha256_file(path)
        if digest != entry.get("sha256"):
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
        entries.append({
            "relative_path": relative,
            "sha256": sha256_bytes(data),
            "size": len(data),
        })

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
    manifest = load_manifest()
    inventory = validate_inventory(manifest)
    total = sum(path.stat().st_size for _, path in inventory)
    print("DRY RUN - no file contents will be modified")
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
    config.RECOVERY_ROOT.mkdir(parents=True, exist_ok=True)
    reject_link(config.RECOVERY_ROOT)
    content = config.KEY_LABEL + b"\n" + base64.b64encode(key) + b"\n"
    atomic_write(config.KEY_FILE, content, config.RECOVERY_ROOT)
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


def create_ransom_note(session_id: str) -> None:
    note = (
        "THIS IS A CYBERSECURITY LAB SIMULATION. NO REAL FILES WERE TARGETED.\n\n"
        "SafeRansomSim-Lab demonstrates constrained file-encryption telemetry and recovery.\n"
        "There are no payment instructions, cryptocurrency addresses, attacker contacts, or Tor links.\n"
    ).encode()
    atomic_write(config.RANSOM_NOTE, note, config.TARGET_ROOT)
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

    manifest = load_manifest()
    inventory = validate_inventory(manifest)
    if config.KEY_FILE.exists():
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
            raise SafetyError(f"Backup already exists; refusing overwrite: {relative}")
        atomic_write(backup, before, config.BACKUP_ROOT)
        if sha256_file(backup) != entry["sha256"]:
            raise SafetyError(f"Backup verification failed: {relative}")

        nonce = secrets.token_bytes(12)
        aad = ("SafeRansomSim-Lab:" + relative).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, before, aad)
        locked = path.with_name(path.name + config.LOCKED_SUFFIX)
        canonical_within(locked, config.TARGET_ROOT)
        if locked.exists() or locked.is_symlink():
            raise SafetyError(f"Locked output already exists: {relative}")
        blob = config.ENCRYPTED_MAGIC + nonce + ciphertext
        atomic_write(locked, blob, config.TARGET_ROOT)
        encrypted_hash = sha256_file(locked)

        # Original is disposable, manifest-owned, marker-verified, and backed up.
        path.unlink()
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        encrypted_count += 1
        log_event(
            "FILE_ENCRYPTION_COMPLETED",
            session_id,
            source_file=relative,
            destination_file=relative + config.LOCKED_SUFFIX,
            sha256_before=entry["sha256"],
            sha256_after=encrypted_hash,
            bytes_processed=len(before),
            elapsed_ms=elapsed_ms,
            success=True,
            safety_validation_result="pass",
        )

    if encrypted_count:
        create_ransom_note(session_id)
    print(f"Controlled simulation completed: {encrypted_count} disposable file(s) encrypted.")
    print(f"Recovery key: {config.KEY_FILE}")


def recover() -> None:
    session_id = uuid.uuid4().hex
    require_authorization(session_id)
    manifest = load_manifest()
    key = read_key()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    log_event("RECOVERY_STARTED", session_id, manifest_files=len(manifest["files"]))
    recovered = 0
    matched = 0
    failed = 0

    for entry in manifest["files"]:
        relative = entry["relative_path"]
        original = target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        canonical_within(locked, config.TARGET_ROOT)

        if original.is_file() and sha256_file(original) == entry["sha256"]:
            matched += 1
            continue
        if not locked.is_file():
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason="locked_file_missing")
            continue
        reject_link(locked)
        blob = locked.read_bytes()
        if len(blob) < len(config.ENCRYPTED_MAGIC) + 12 or not blob.startswith(config.ENCRYPTED_MAGIC):
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason="invalid_locked_format")
            continue

        nonce_start = len(config.ENCRYPTED_MAGIC)
        nonce = blob[nonce_start:nonce_start + 12]
        ciphertext = blob[nonce_start + 12:]
        aad = ("SafeRansomSim-Lab:" + relative).encode("utf-8")
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:  # cryptography raises InvalidTag on tamper/wrong key
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason=type(exc).__name__)
            continue

        atomic_write(original, plaintext, config.TARGET_ROOT)
        digest = sha256_file(original)
        recovered += 1
        if digest == entry["sha256"]:
            matched += 1
            locked.unlink()
            log_event("FILE_RECOVERED", session_id, source_file=relative + config.LOCKED_SUFFIX, destination_file=relative)
            log_event("HASH_VERIFICATION_SUCCESS", session_id, source_file=relative, sha256_after=digest)
        else:
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, sha256_after=digest)

    if failed == 0 and matched == len(manifest["files"]) and config.RANSOM_NOTE.exists():
        reject_link(config.RANSOM_NOTE)
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
    manifest_files = 0
    originals = 0
    locked = 0
    if manifest_exists:
        try:
            manifest = load_manifest()
            manifest_files = len(manifest["files"])
            for entry in manifest["files"]:
                p = target_path(entry["relative_path"])
                originals += int(p.is_file())
                locked += int(p.with_name(p.name + config.LOCKED_SUFFIX).is_file())
        except SafetyError as exc:
            print(f"Manifest safety error: {exc}")

    print(f"Lab root          : {config.LAB_ROOT}")
    print(f"Fixed target      : {config.TARGET_ROOT}")
    print(f"Manifest present  : {manifest_exists}")
    print(f"Manifest files    : {manifest_files}")
    print(f"Original files    : {originals}")
    print(f"Locked files      : {locked}")
    print(f"Recovery key      : {config.KEY_FILE.is_file()}")
    print(f"Kill switch       : {config.STOP_FILE.exists()}")
    print(f"Authorization     : {config.AUTH_FILE.is_file()}")


def cleanup() -> None:
    session_id = uuid.uuid4().hex
    require_authorization(session_id)
    # Fixed, non-user-configurable runtime paths only.
    for root in (config.TARGET_ROOT, config.BACKUP_ROOT, config.LOG_ROOT, config.RECOVERY_ROOT):
        canonical_within(root, config.LAB_ROOT)
        if root.exists() or root.is_symlink():
            reject_link(root)
            shutil.rmtree(root)
    for path in (config.MANIFEST_FILE, config.STOP_FILE):
        canonical_within(path, config.LAB_ROOT)
        if path.exists() or path.is_symlink():
            reject_link(path)
            path.unlink()
    print("Removed simulator-generated runtime artifacts. Authorization file was preserved.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe, fixed-sandbox ransomware behavior simulator")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--setup", action="store_true", help="create disposable lab files")
    modes.add_argument("--dry-run", action="store_true", help="show eligible files without modification")
    modes.add_argument("--simulate", action="store_true", help="run controlled fixed-sandbox encryption simulation")
    modes.add_argument("--recover", action="store_true", help="decrypt and SHA-256 verify disposable lab files")
    modes.add_argument("--status", action="store_true", help="show current lab state")
    modes.add_argument("--cleanup", action="store_true", help="remove simulator-generated runtime artifacts")
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
