from __future__ import annotations

import ast
from pathlib import Path

from saferansomsim import config
from saferansomsim.cli import build_parser

FORBIDDEN_IMPORT_ROOTS = {"socket", "requests", "subprocess", "paramiko", "ftplib", "telnetlib", "smtplib", "httpx", "aiohttp", "winreg"}
FORBIDDEN_SOURCE_TOKENS = {"schtasks", "powershell.exe", "cmd.exe", "vssadmin", "wbadmin", "bcdedit", "wevtutil", "credential dumping", "uac bypass"}


def _package_files() -> list[Path]:
    package = Path(__file__).resolve().parents[1] / "saferansomsim"
    return sorted(package.glob("*.py"))


def test_cli_exposes_no_arbitrary_target_or_external_input_option() -> None:
    options = {option for action in build_parser()._actions for option in action.option_strings}
    for forbidden in (
        "--target", "--path", "--directory", "--root", "--share", "--host",
        "--dataset", "--input", "--output", "--response-file", "--config-file",
        "--command", "--url", "--endpoint",
    ):
        assert forbidden not in options


def test_scenario_cli_choices_are_fixed() -> None:
    actions = {option: action for action in build_parser()._actions for option in action.option_strings}
    expected = {"basic", "interrupted", "recovery-failure", "false-positive"}
    for option in ("--exercise", "--replay-scenario", "--score-exercise", "--verify-evidence"):
        assert set(actions[option].choices) == expected


def test_fixed_target_is_test123_under_lab_root() -> None:
    assert config.TARGET_ROOT == config.LAB_ROOT / "test123"
    assert config.REPORT_ROOT == config.LAB_ROOT / "reports"


def test_package_imports_no_network_remote_execution_or_process_modules() -> None:
    violations: list[str] = []
    for path in _package_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots = {node.module.split(".")[0]}
            else:
                continue
            for root in roots & FORBIDDEN_IMPORT_ROOTS:
                violations.append(f"{path.name}: {root}")
    assert not violations, "Forbidden capability import(s): " + ", ".join(violations)


def test_package_contains_no_persistence_or_evasion_command_tokens() -> None:
    violations: list[str] = []
    for path in _package_files():
        source = path.read_text(encoding="utf-8").lower()
        for token in FORBIDDEN_SOURCE_TOKENS:
            if token in source:
                violations.append(f"{path.name}: {token}")
    assert not violations, "Forbidden safety-contract token(s): " + ", ".join(violations)


def test_compatibility_entrypoint_stays_thin() -> None:
    root = Path(__file__).resolve().parents[1]
    lines = (root / "simulator.py").read_text(encoding="utf-8").splitlines()
    assert len(lines) < 60
    required_modules = {
        "safety.py", "manifest.py", "crypto_demo.py", "telemetry.py", "reporting.py",
        "engine.py", "cli.py", "scenarios.py", "exercises.py", "scoring.py",
        "detection_validation.py", "evidence.py", "schema_validation.py",
    }
    assert required_modules.issubset({path.name for path in (root / "saferansomsim").glob("*.py")})
