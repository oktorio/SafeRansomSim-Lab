from __future__ import annotations

from pathlib import Path


def test_detection_pack_contains_lab_specific_sigma_rules() -> None:
    root = Path(__file__).resolve().parents[1] / "detections"
    locked = (root / "sigma" / "simulated_locked_extension.yml").read_text(encoding="utf-8")
    note = (root / "sigma" / "simulated_ransom_note.yml").read_text(encoding="utf-8")
    assert ".SIMULATED_LOCKED" in locked
    assert "SIMULATED_RANSOM_NOTE.txt" in note
    assert "status: test" in locked
    assert "status: test" in note


def test_detection_pack_is_documentation_and_rules_only() -> None:
    root = Path(__file__).resolve().parents[1] / "detections"
    executable_suffixes = {".py", ".ps1", ".sh", ".bat", ".cmd", ".exe", ".dll"}
    assert not [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in executable_suffixes]
