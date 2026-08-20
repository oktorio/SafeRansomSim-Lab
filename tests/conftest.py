from __future__ import annotations

from pathlib import Path

import pytest

from saferansomsim import config
from saferansomsim.engine import setup


@pytest.fixture
def isolated_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "repo"
    base.mkdir()
    lab = base / "ransomware_lab"

    monkeypatch.setattr(config, "BASE_DIR", base)
    monkeypatch.setattr(config, "LAB_ROOT", lab)
    monkeypatch.setattr(config, "TARGET_ROOT", lab / "test123")
    monkeypatch.setattr(config, "BACKUP_ROOT", lab / "backups")
    monkeypatch.setattr(config, "LOG_ROOT", lab / "logs")
    monkeypatch.setattr(config, "RECOVERY_ROOT", lab / "recovery")
    monkeypatch.setattr(config, "REPORT_ROOT", lab / "reports")
    monkeypatch.setattr(config, "MANIFEST_FILE", lab / "manifest.json")
    monkeypatch.setattr(config, "AUTH_FILE", lab / "AUTHORIZED_LAB.txt")
    monkeypatch.setattr(config, "STOP_FILE", lab / "STOP_SIMULATION")
    monkeypatch.setattr(config, "RANSOM_NOTE", lab / "test123" / "SIMULATED_RANSOM_NOTE.txt")
    monkeypatch.setattr(config, "KEY_FILE", lab / "recovery" / "demo_key.bin")
    monkeypatch.setattr(config, "EVENT_LOG", lab / "logs" / "events.jsonl")

    setup()
    config.AUTH_FILE.write_text(config.AUTH_PHRASE + "\n", encoding="utf-8")
    return lab
