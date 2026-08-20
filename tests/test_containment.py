from __future__ import annotations

import json
from pathlib import Path

import pytest

from saferansomsim import config
from saferansomsim import engine
from saferansomsim.manifest import load_manifest, validate_inventory
from saferansomsim.safety import SafetyError, target_path, validate_manifest_relative


def test_rejects_traversal_absolute_drive_network_and_uri_paths() -> None:
    bad_paths = ["../escape.txt", "..\\escape.txt", "folder/../escape.txt", "folder\\..\\escape.txt", "/etc/passwd", "C:\\Users\\Example\\file.txt", "\\\\server\\share\\file.txt", "https://example.test/file.txt", "a/b/c/d/e.txt"]
    for value in bad_paths:
        with pytest.raises(SafetyError):
            validate_manifest_relative(value)


def test_rejects_home_and_common_user_directories() -> None:
    for path in (Path.home(), Path.home() / "Desktop", Path.home() / "Documents", Path.home() / "Downloads"):
        with pytest.raises(SafetyError):
            validate_manifest_relative(str(path))


def test_extra_file_is_not_manifest_eligible(isolated_lab: Path) -> None:
    extra = config.TARGET_ROOT / "not-in-manifest.txt"
    extra.write_bytes(config.TEST_MARKER + b"extra disposable-looking file\n")
    inventory = validate_inventory(load_manifest())
    eligible = {entry["relative_path"] for entry, _ in inventory}
    assert "not-in-manifest.txt" not in eligible
    assert extra.exists()


def test_missing_authorization_aborts_simulation(isolated_lab: Path) -> None:
    config.AUTH_FILE.unlink()
    with pytest.raises(SafetyError, match="Authorization marker missing"):
        engine.simulate()


def test_symlink_escape_is_rejected(isolated_lab: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = config.TARGET_ROOT / "escape-link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable on this platform")
    with pytest.raises(SafetyError):
        target_path("escape-link.txt")


def test_manifest_file_count_limit(isolated_lab: Path) -> None:
    manifest = load_manifest()
    prototype = manifest["files"][0]
    manifest["files"] = [{**prototype, "relative_path": f"f-{index}.txt"} for index in range(config.MAX_FILES + 1)]
    config.MANIFEST_FILE.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SafetyError, match="maximum file count"):
        load_manifest()


def test_duplicate_manifest_path_is_rejected(isolated_lab: Path) -> None:
    manifest = load_manifest()
    manifest["files"].append(dict(manifest["files"][0]))
    config.MANIFEST_FILE.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SafetyError, match="Duplicate manifest path"):
        validate_inventory(load_manifest())


def test_individual_and_total_size_limits(isolated_lab: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = load_manifest()
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 10)
    with pytest.raises(SafetyError, match="File exceeds"):
        validate_inventory(manifest)
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 10 * 1024 * 1024)
    monkeypatch.setattr(config, "MAX_TOTAL_SIZE", 10)
    with pytest.raises(SafetyError, match="Total data exceeds"):
        validate_inventory(manifest)
