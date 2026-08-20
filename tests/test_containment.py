from __future__ import annotations

import json
from pathlib import Path

import pytest

import config
import simulator


def test_rejects_traversal_absolute_drive_and_network_paths() -> None:
    bad_paths = [
        "../escape.txt",
        "/etc/passwd",
        "C:\\Users\\Example\\file.txt",
        "\\\\server\\share\\file.txt",
        "a/b/c/d/e.txt",
    ]
    for value in bad_paths:
        with pytest.raises(simulator.SafetyError):
            simulator.validate_manifest_relative(value)


def test_rejects_home_and_common_user_directories() -> None:
    candidates = [
        Path.home(),
        Path.home() / "Desktop",
        Path.home() / "Documents",
        Path.home() / "Downloads",
    ]
    for path in candidates:
        with pytest.raises(simulator.SafetyError):
            simulator.validate_manifest_relative(str(path))


def test_extra_file_is_not_manifest_eligible(isolated_lab: Path) -> None:
    extra = config.TARGET_ROOT / "not-in-manifest.txt"
    extra.write_bytes(config.TEST_MARKER + b"extra disposable-looking file\n")

    manifest = simulator.load_manifest()
    inventory = simulator.validate_inventory(manifest)
    eligible = {entry["relative_path"] for entry, _ in inventory}

    assert "not-in-manifest.txt" not in eligible
    assert extra.exists()


def test_missing_authorization_aborts_simulation(isolated_lab: Path) -> None:
    config.AUTH_FILE.unlink()
    with pytest.raises(simulator.SafetyError, match="Authorization marker missing"):
        simulator.simulate()


def test_symlink_escape_is_rejected(isolated_lab: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = config.TARGET_ROOT / "escape-link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable on this platform")

    with pytest.raises(simulator.SafetyError):
        simulator.target_path("escape-link.txt")


def test_manifest_file_count_limit(isolated_lab: Path) -> None:
    manifest = simulator.load_manifest()
    prototype = manifest["files"][0]
    manifest["files"] = [
        {
            **prototype,
            "relative_path": f"f-{index}.txt",
        }
        for index in range(config.MAX_FILES + 1)
    ]
    config.MANIFEST_FILE.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(simulator.SafetyError, match="maximum file count"):
        simulator.load_manifest()


def test_total_size_limit_is_enforced(isolated_lab: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "MAX_TOTAL_SIZE", 10)
    manifest = simulator.load_manifest()
    with pytest.raises(simulator.SafetyError, match="Total data exceeds"):
        simulator.validate_inventory(manifest)
