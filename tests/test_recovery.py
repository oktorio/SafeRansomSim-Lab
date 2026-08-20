from __future__ import annotations

from pathlib import Path

from saferansomsim import config
from saferansomsim import engine
from saferansomsim.manifest import load_manifest
from saferansomsim.safety import sha256_file, target_path


def test_simulation_and_full_hash_verified_recovery(isolated_lab: Path) -> None:
    manifest = load_manifest()
    expected = {entry["relative_path"]: entry["sha256"] for entry in manifest["files"]}
    engine.simulate()
    for relative in expected:
        original = target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert not original.exists()
        assert locked.is_file()
    engine.recover()
    for relative, digest in expected.items():
        original = target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert original.is_file()
        assert sha256_file(original) == digest
        assert not locked.exists()
    assert not config.RANSOM_NOTE.exists()


def test_recovery_refuses_to_overwrite_conflicting_file(isolated_lab: Path) -> None:
    relative = load_manifest()["files"][0]["relative_path"]
    engine.simulate()
    original = target_path(relative)
    locked = original.with_name(original.name + config.LOCKED_SUFFIX)
    conflict = b"user-created conflict that must be preserved\n"
    original.write_bytes(conflict)
    engine.recover()
    assert original.read_bytes() == conflict
    assert locked.is_file()
    assert config.RANSOM_NOTE.is_file()


def test_cleanup_preserves_unmanifested_file(isolated_lab: Path) -> None:
    extra = config.TARGET_ROOT / "do-not-delete-me.txt"
    content = b"not owned by the simulator\n"
    extra.write_bytes(content)
    engine.cleanup()
    assert extra.is_file()
    assert extra.read_bytes() == content
    assert config.MANIFEST_FILE.is_file()
    assert config.AUTH_FILE.is_file()


def test_cleanup_preserves_forged_locked_artifact(isolated_lab: Path) -> None:
    relative = load_manifest()["files"][0]["relative_path"]
    engine.simulate()
    locked = target_path(relative).with_name(target_path(relative).name + config.LOCKED_SUFFIX)
    forged = config.ENCRYPTED_MAGIC + b"not-a-valid-aes-gcm-artifact"
    locked.write_bytes(forged)
    engine.cleanup()
    assert locked.read_bytes() == forged
    assert config.MANIFEST_FILE.is_file()
    assert config.KEY_FILE.is_file()


def test_cleanup_removes_verified_runtime_but_preserves_reports(isolated_lab: Path) -> None:
    engine.simulate()
    reports_before = set(config.REPORT_ROOT.glob("run-*"))
    assert reports_before
    engine.cleanup()
    assert not config.MANIFEST_FILE.exists()
    assert not config.KEY_FILE.exists()
    assert reports_before.issubset(set(config.REPORT_ROOT.glob("run-*")))
