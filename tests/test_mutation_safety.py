from __future__ import annotations

from pathlib import Path

import pytest

from saferansomsim import config
from saferansomsim.cli import build_parser
from saferansomsim.safety import SafetyError, ensure_lab_integrity


def test_mutated_target_outside_lab_is_rejected(isolated_lab: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "TARGET_ROOT", tmp_path / "outside-target")
    with pytest.raises(SafetyError):
        ensure_lab_integrity(create=False)


def test_arbitrary_input_mutations_are_rejected_by_cli() -> None:
    parser = build_parser()
    for args in (["--target", "x"], ["--dataset", "x"], ["--response-file", "x"], ["--input", "x"]):
        with pytest.raises(SystemExit):
            parser.parse_args(args)


def test_fixed_scenario_choices_cannot_be_replaced_with_path() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--exercise", "../../tmp"])
