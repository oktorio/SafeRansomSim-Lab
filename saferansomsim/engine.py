"""Orchestration for the fixed-sandbox simulator and recovery workflow."""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

from . import config
from .crypto_demo import decrypt_blob, encrypt_blob, generate_demo_key, locked_file_is_simulator_owned, read_key, write_key
from .manifest import load_manifest, setup as create_manifest_lab, validate_inventory
from .reporting import write_report
from .safety import SafetyError, atomic_write, backup_path, canonical_within, ensure_lab_integrity, is_reparse_point, kill_switch_present, locked_path, reject_link, reject_link_components, require_authorization, sha256_bytes, sha256_file, target_path
from .telemetry import events_log_is_simulator_owned, log_event


def ransom_note_bytes() -> bytes:
    return (
        "THIS IS A CYBERSECURITY LAB SIMULATION. NO REAL FILES WERE TARGETED.\n\n"
        "SafeRansomSim-Lab demonstrates constrained file-encryption telemetry and recovery.\n"
        "There are no payment instructions, cryptocurrency addresses, attacker contacts, or Tor links.\n"
    ).encode()


def _show_report(paths: tuple[Path, Path]) -> None:
    print(f"JSON report        : {paths[0]}")
    print(f"HTML report        : {paths[1]}")


def setup() -> None:
    session_id = uuid.uuid4().hex
    manifest = create_manifest_lab()
    log_event("SETUP_COMPLETED", session_id, manifest_files=len(manifest["files"]))
    report = write_report(session_id, "setup", {"manifest_files": len(manifest["files"]), "fixed_target": str(config.TARGET_ROOT), "authorization_created": False})
    print(f"Created {len(manifest['files'])} disposable test files in {config.TARGET_ROOT}")
    print("Authorization was NOT created automatically.")
    print("Copy AUTHORIZED_LAB.example.txt to AUTHORIZED_LAB.txt before --simulate.")
    _show_report(report)


def dry_run() -> None:
    session_id = uuid.uuid4().hex
    inventory = validate_inventory(load_manifest())
    total = sum(path.stat().st_size for _, path in inventory)
    log_event("DRY_RUN_STARTED", session_id, eligible_files=len(inventory), bytes_total=total)
    print("DRY RUN - no test-file contents will be modified")
    print(f"Fixed target: {config.TARGET_ROOT}")
    print(f"Eligible files: {len(inventory)} | Total bytes: {total}")
    for entry, path in inventory:
        log_event("FILE_DISCOVERED", session_id, source_file=entry["relative_path"], bytes_processed=path.stat().st_size, sha256_before=entry["sha256"], safety_validation_result="pass")
        print(f"  WOULD PROCESS  {entry['relative_path']}  sha256={entry['sha256'][:16]}...")
    log_event("DRY_RUN_COMPLETED", session_id, eligible_files=len(inventory), bytes_total=total)
    report = write_report(session_id, "dry-run", {"eligible_files": len(inventory), "bytes_total": total, "files_modified": 0, "result": "PASS"})
    _show_report(report)


def create_ransom_note(session_id: str) -> None:
    atomic_write(config.RANSOM_NOTE, ransom_note_bytes(), config.TARGET_ROOT)
    log_event("RANSOM_NOTE_CREATED", session_id, destination_file=config.RANSOM_NOTE.name)


def simulate(initial_access: bool = False) -> None:
    session_id = uuid.uuid4().hex
    require_authorization()
    log_event("AUTHORIZATION_VERIFIED", session_id, safety_validation_result="pass")
    if initial_access:
        log_event("SIMULATED_EMAIL_ATTACHMENT_EXECUTION", session_id, detail="Harmless local telemetry event only; no email payload or delivery mechanism exists.")

    inventory = validate_inventory(load_manifest())
    if config.KEY_FILE.exists() or config.KEY_FILE.is_symlink():
        reject_link(config.KEY_FILE)
        raise SafetyError("Existing demo recovery key detected; recover/cleanup before another simulation.")

    key = generate_demo_key()
    write_key(key)
    log_event("SIMULATION_STARTED", session_id, eligible_files=len(inventory))
    encrypted_count = 0
    bytes_processed = 0
    stopped = False
    for entry, path in inventory:
        if kill_switch_present():
            stopped = True
            log_event("SIMULATION_STOPPED", session_id, reason="kill_switch")
            break

        relative = entry["relative_path"]
        started = time.perf_counter()
        before = path.read_bytes()
        log_event("FILE_ENCRYPTION_STARTED", session_id, source_file=relative, sha256_before=entry["sha256"], bytes_processed=len(before))

        backup = backup_path(relative)
        if backup.exists() or backup.is_symlink():
            reject_link(backup)
            raise SafetyError(f"Backup already exists; refusing overwrite: {relative}")
        atomic_write(backup, before, config.BACKUP_ROOT)
        if sha256_file(backup) != entry["sha256"]:
            raise SafetyError(f"Backup verification failed: {relative}")

        locked = locked_path(relative)
        if locked.exists() or locked.is_symlink():
            reject_link(locked)
            raise SafetyError(f"Locked output already exists: {relative}")
        atomic_write(locked, encrypt_blob(before, relative, key), config.TARGET_ROOT)
        encrypted_hash = sha256_file(locked)
        path.unlink()
        encrypted_count += 1
        bytes_processed += len(before)
        log_event("FILE_ENCRYPTION_COMPLETED", session_id, source_file=relative, destination_file=relative + config.LOCKED_SUFFIX, sha256_before=entry["sha256"], sha256_after=encrypted_hash, bytes_processed=len(before), elapsed_ms=round((time.perf_counter() - started) * 1000, 3), success=True, safety_validation_result="pass")

    if encrypted_count:
        create_ransom_note(session_id)
    log_event("SIMULATION_COMPLETED", session_id, encrypted_files=encrypted_count, skipped_files=len(inventory) - encrypted_count, bytes_processed=bytes_processed, kill_switch_triggered=stopped)
    report = write_report(session_id, "simulate-initial-access" if initial_access else "simulate", {"eligible_files": len(inventory), "encrypted_files": encrypted_count, "skipped_files": len(inventory) - encrypted_count, "bytes_processed": bytes_processed, "kill_switch_triggered": stopped, "recovery_key_present": config.KEY_FILE.is_file(), "result": "STOPPED_BY_KILL_SWITCH" if stopped else "COMPLETED"})
    print(f"Controlled simulation completed: {encrypted_count} disposable file(s) encrypted.")
    print(f"Recovery key: {config.KEY_FILE}")
    _show_report(report)


def recover() -> None:
    session_id = uuid.uuid4().hex
    require_authorization()
    log_event("AUTHORIZATION_VERIFIED", session_id, safety_validation_result="pass")
    manifest = load_manifest()
    key = read_key()
    log_event("RECOVERY_STARTED", session_id, manifest_files=len(manifest["files"]))
    recovered = 0
    matched = 0
    failed = 0

    for entry in manifest["files"]:
        relative = entry["relative_path"]
        original = target_path(relative)
        locked = locked_path(relative)
        if original.exists() or original.is_symlink():
            reject_link(original)
            if original.is_file() and sha256_file(original) == entry["sha256"]:
                matched += 1
                continue
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason="original_path_conflict_refusing_overwrite")
            continue
        if not locked.is_file():
            failed += 1
            log_event("HASH_VERIFICATION_FAILURE", session_id, source_file=relative, reason="locked_file_missing")
            continue
        reject_link(locked)
        try:
            plaintext = decrypt_blob(locked.read_bytes(), relative, key)
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

    full_success = failed == 0 and matched == len(manifest["files"])
    if full_success and config.RANSOM_NOTE.exists():
        reject_link(config.RANSOM_NOTE)
        if config.RANSOM_NOTE.is_file() and config.RANSOM_NOTE.read_bytes() == ransom_note_bytes():
            config.RANSOM_NOTE.unlink()
    log_event("RECOVERY_COMPLETED", session_id, manifest_files=len(manifest["files"]), files_recovered=recovered, hash_matched=matched, hash_failed=failed, full_recovery=full_success)
    report = write_report(session_id, "recover", {"manifest_files": len(manifest["files"]), "files_recovered": recovered, "hash_matched": matched, "hash_failed": failed, "full_recovery": full_success, "result": "FULL_RECOVERY_SUCCESSFUL" if full_success else "RECOVERY_INCOMPLETE"})
    print("Recovery verification")
    print(f"Files in manifest : {len(manifest['files'])}")
    print(f"Files recovered   : {recovered}")
    print(f"Hash matched      : {matched}")
    print(f"Hash failed       : {failed}")
    print("RESULT: FULL RECOVERY SUCCESSFUL" if full_success else "RESULT: RECOVERY INCOMPLETE")
    _show_report(report)


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
                locked = locked_path(entry["relative_path"])
                if locked.exists() or locked.is_symlink():
                    reject_link(locked)
                locked_count += int(locked.is_file())
        except SafetyError as exc:
            print(f"Manifest safety error: {exc}")
    reports = 0
    if config.REPORT_ROOT.exists():
        reject_link(config.REPORT_ROOT)
        reports = sum(1 for path in config.REPORT_ROOT.glob("run-*.json") if path.is_file())
    print(f"Project version    : {config.PROJECT_VERSION}")
    print(f"Lab root           : {config.LAB_ROOT}")
    print(f"Fixed target       : {config.TARGET_ROOT}")
    print(f"Manifest present   : {manifest_exists}")
    print(f"Manifest files     : {manifest_files}")
    print(f"Original files     : {originals}")
    print(f"Locked files       : {locked_count}")
    print(f"Recovery key       : {config.KEY_FILE.is_file()}")
    print(f"Kill switch        : {config.STOP_FILE.exists()}")
    print(f"Authorization      : {config.AUTH_FILE.is_file()}")
    print(f"JSON reports       : {reports}")


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
    for parent in sorted(parents, key=lambda item: len(item.parts), reverse=True):
        if parent.exists() and not parent.is_symlink():
            reject_link(parent)
            try:
                parent.rmdir()
            except OSError:
                pass


def _record_unknown_runtime_files(root: Path, conflicts: list[str], ignored: set[Path] | None = None) -> None:
    if not root.exists():
        return
    ignored = ignored or set()
    reject_link(root)
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
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
        for name in names:
            child = current_path / name
            if child in ignored:
                continue
            conflicts.append(f"preserved unknown runtime file: {child.relative_to(config.LAB_ROOT)}")


def cleanup() -> None:
    session_id = uuid.uuid4().hex
    require_authorization()
    log_event("AUTHORIZATION_VERIFIED", session_id, safety_validation_result="pass")
    log_event("CLEANUP_STARTED", session_id)
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
        locked = locked_path(relative)
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
            if locked_file_is_simulator_owned(locked, relative, entry["sha256"], cleanup_key):
                locked.unlink()
            else:
                conflicts.append(f"preserved unverified/conflicting locked path: {relative + config.LOCKED_SUFFIX}")
        backup = backup_path(relative)
        backup_paths.append(backup)
        if not _delete_if_hash(backup, config.BACKUP_ROOT, entry["sha256"]):
            conflicts.append(f"preserved unknown/conflicting backup: {relative}")

    if not _delete_if_exact_file(config.RANSOM_NOTE, config.TARGET_ROOT, ransom_note_bytes()):
        conflicts.append(f"preserved unknown/conflicting note: {config.RANSOM_NOTE.name}")
    events = config.EVENT_LOG
    canonical_within(events, config.LOG_ROOT)
    if events.exists() or events.is_symlink():
        reject_link(events)
        if events_log_is_simulator_owned(events):
            events.unlink()
        else:
            conflicts.append("preserved unknown/conflicting events log")
    _prune_manifest_parents(target_paths, config.TARGET_ROOT)
    _prune_manifest_parents(backup_paths, config.BACKUP_ROOT)
    for root, ignored in ((config.TARGET_ROOT, set()), (config.BACKUP_ROOT, set()), (config.LOG_ROOT, set()), (config.RECOVERY_ROOT, {config.KEY_FILE})):
        _record_unknown_runtime_files(root, conflicts, ignored)

    if conflicts:
        report = write_report(session_id, "cleanup", {"result": "PRESERVED_CONFLICTS", "conflict_count": len(set(conflicts)), "reports_preserved": True})
        print("Cleanup preserved one or more non-owned/conflicting artifacts:")
        for item in sorted(set(conflicts)):
            print(f"  - {item}")
        print("Manifest, reports, and recovery key were preserved so the lab state can be reviewed safely.")
        _show_report(report)
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
    report = write_report(session_id, "cleanup", {"result": "CLEANUP_SUCCESSFUL", "manifest_removed": True, "reports_preserved": True})
    print("Removed only cryptographically or hash-verified simulator-owned runtime artifacts. Authorization, kill-switch, and reports were preserved.")
    _show_report(report)
