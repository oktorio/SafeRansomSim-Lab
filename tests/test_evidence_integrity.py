from __future__ import annotations

import json
from pathlib import Path

from saferansomsim.evidence import verify_manifest
from saferansomsim.exercises import prepare_exercise, score_exercise


def test_prepared_exercise_has_verified_evidence_manifest(isolated_lab: Path) -> None:
    root = prepare_exercise("basic")
    result = verify_manifest(root, "basic")
    assert result["status"] == "pass"
    assert result["checked"] >= 3


def test_tampered_synthetic_evidence_is_detected(isolated_lab: Path) -> None:
    root = prepare_exercise("basic")
    events = root / "evidence" / "events.jsonl"
    events.write_text(events.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
    result = verify_manifest(root, "basic")
    assert result["status"] == "fail"
    assert any("evidence/events.jsonl" in item for item in result["errors"])


def test_scoring_records_response_and_score_artifact_hashes(isolated_lab: Path) -> None:
    root = prepare_exercise("false-positive")
    response = root / "analyst-response.json"
    payload = json.loads(response.read_text(encoding="utf-8"))
    payload.update({
        "classification": "benign_lookalike",
        "identified_event_types": ["BENIGN_FILE_CREATED", "BENIGN_PROCESS_EXITED"],
        "containment_actions": ["do_not_trigger_emergency_containment", "document_rationale"],
        "recovery_actions": ["no_recovery_required"],
        "false_positive_assessment": "false_positive_likely",
    })
    response.write_text(json.dumps(payload), encoding="utf-8")
    result = score_exercise("false-positive")
    assert result["score"] == 100
    final = verify_manifest(root, "false-positive")
    assert final["status"] == "pass"
    assert final["checked"] >= 6
