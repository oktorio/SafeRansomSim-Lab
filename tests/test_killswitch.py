from __future__ import annotations

from pathlib import Path

import config
import simulator


def test_kill_switch_stops_before_first_file(isolated_lab: Path) -> None:
    manifest = simulator.load_manifest()
    expected = {entry["relative_path"]: entry["sha256"] for entry in manifest["files"]}
    config.STOP_FILE.write_text("stop\n", encoding="utf-8")

    simulator.simulate()

    for relative, digest in expected.items():
        original = simulator.target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert original.is_file()
        assert simulator.sha256_file(original) == digest
        assert not locked.exists()
    assert not config.RANSOM_NOTE.exists()

    events = (config.LOG_ROOT / "events.jsonl").read_text(encoding="utf-8")
    assert "SIMULATION_STOPPED" in events
    assert "kill_switch" in events


def test_mid_run_kill_switch_remains_fully_recoverable(
    isolated_lab: Path,
    monkeypatch,
) -> None:
    manifest = simulator.load_manifest()
    expected = {entry["relative_path"]: entry["sha256"] for entry in manifest["files"]}
    relatives = list(expected)
    real_check = simulator.check_kill_switch
    calls = 0

    def staged_kill_switch(session_id: str) -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            config.STOP_FILE.write_text("stop after first file\n", encoding="utf-8")
        return real_check(session_id)

    monkeypatch.setattr(simulator, "check_kill_switch", staged_kill_switch)
    simulator.simulate()

    first = simulator.target_path(relatives[0])
    first_locked = first.with_name(first.name + config.LOCKED_SUFFIX)
    assert not first.exists()
    assert first_locked.is_file()

    for relative in relatives[1:]:
        original = simulator.target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert original.is_file()
        assert simulator.sha256_file(original) == expected[relative]
        assert not locked.exists()

    assert config.RANSOM_NOTE.is_file()
    config.STOP_FILE.unlink()

    simulator.recover()

    for relative, digest in expected.items():
        original = simulator.target_path(relative)
        locked = original.with_name(original.name + config.LOCKED_SUFFIX)
        assert original.is_file()
        assert simulator.sha256_file(original) == digest
        assert not locked.exists()

    assert not config.RANSOM_NOTE.exists()
