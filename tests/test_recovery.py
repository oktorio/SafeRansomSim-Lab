from __future__ import annotations

from pathlib import Path

import config
import simulator


def test_simulation_and_full_hash_verified_recovery(isolated_lab: Path) -> None:
    manifest = simulator.load_manifest()
    expected = {entry["relative_path"]: entry["sha256"] for entry in manifest["files"]}

    simulator.simulate()

    for relative in expected:
        original = simulator.target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert not original.exists()
        assert locked.is_file()
    assert config.KEY_FILE.is_file()
    assert config.RANSOM_NOTE.is_file()

    simulator.recover()

    for relative, digest in expected.items():
        original = simulator.target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert original.is_file()
        assert simulator.sha256_file(original) == digest
        assert not locked.exists()
    assert not config.RANSOM_NOTE.exists()


def test_recovery_refuses_to_overwrite_conflicting_file(isolated_lab: Path) -> None:
    manifest = simulator.load_manifest()
    relative = manifest["files"][0]["relative_path"]

    simulator.simulate()

    original = simulator.target_path(relative)
    locked = original.with_name(original.name + config.LOCKED_SUFFIX)
    conflict = b"user-created conflict that must be preserved\n"
    original.write_bytes(conflict)

    simulator.recover()

    assert original.read_bytes() == conflict
    assert locked.is_file()
    assert config.RANSOM_NOTE.is_file()


def test_cleanup_preserves_unmanifested_file(isolated_lab: Path) -> None:
    extra = config.TARGET_ROOT / "do-not-delete-me.txt"
    content = b"not owned by the simulator\n"
    extra.write_bytes(content)

    simulator.cleanup()

    assert extra.is_file()
    assert extra.read_bytes() == content
    assert config.AUTH_FILE.is_file()
