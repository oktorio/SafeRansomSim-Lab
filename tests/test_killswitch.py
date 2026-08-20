from __future__ import annotations

from pathlib import Path

import pytest

from saferansomsim import config, engine
from saferansomsim.manifest import load_manifest
from saferansomsim.safety import sha256_file, target_path


def test_kill_switch_stops_before_first_file(isolated_lab: Path) -> None:
    expected = {entry["relative_path"]: entry["sha256"] for entry in load_manifest()["files"]}
    config.STOP_FILE.write_text("stop\n", encoding="utf-8")
    engine.simulate()
    for relative, digest in expected.items():
        original = target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert original.is_file()
        assert sha256_file(original) == digest
        assert not locked.exists()
    assert not config.RANSOM_NOTE.exists()


def test_mid_run_kill_switch_then_full_recovery(isolated_lab: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expected = {entry["relative_path"]: entry["sha256"] for entry in load_manifest()["files"]}
    calls = {"count": 0}
    def stop_after_first_check() -> bool:
        calls["count"] += 1
        return calls["count"] >= 2
    monkeypatch.setattr(engine, "kill_switch_present", stop_after_first_check)
    engine.simulate()
    locked_count = 0
    for relative in expected:
        original = target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        locked_count += int(locked.is_file())
    assert locked_count == 1
    engine.recover()
    for relative, digest in expected.items():
        original = target_path(relative)
        assert original.is_file()
        assert sha256_file(original) == digest
