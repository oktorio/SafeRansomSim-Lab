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
