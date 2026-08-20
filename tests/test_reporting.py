from __future__ import annotations

import json
from pathlib import Path

import pytest

from saferansomsim import config, engine
from saferansomsim.reporting import write_report
from saferansomsim.safety import SafetyError


def test_dry_run_generates_json_and_html_reports(isolated_lab: Path) -> None:
    before = set(config.REPORT_ROOT.glob("run-*.json"))
    engine.dry_run()
    after = set(config.REPORT_ROOT.glob("run-*.json"))
    created = after - before
    assert len(created) == 1
    json_path = created.pop()
    html_path = json_path.with_suffix(".html")
    assert html_path.is_file()
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == 1
    assert report["project"] == config.PROJECT_NAME
    assert report["project_version"] == config.PROJECT_VERSION
    assert report["operation"] == "dry-run"
    assert report["summary"]["files_modified"] == 0
    assert report["safety_boundary"]["arbitrary_target_supported"] is False
    assert report["safety_boundary"]["network_activity"] == "none_by_design"
    html_text = html_path.read_text(encoding="utf-8")
    assert "Controlled lab evidence" in html_text
    assert config.PROJECT_VERSION in html_text


def test_report_session_id_cannot_escape_report_root(isolated_lab: Path) -> None:
    with pytest.raises(SafetyError):
        write_report("../escape", "test", {"result": "NO"})
