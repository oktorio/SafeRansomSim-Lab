from __future__ import annotations

import json
from pathlib import Path

from saferansomsim import config
from saferansomsim.exercises import load_dataset, prepare_exercise, score_exercise
from saferansomsim.scenarios import SCENARIOS
from saferansomsim.scoring import score_response

EXPECTED_SCENARIOS = {
    "basic", "interrupted", "recovery-failure", "false-positive",
    "benign-backup-burst", "mixed-signal", "telemetry-gap",
}


def _perfect_response(scenario_id: str) -> dict[str, object]:
    scenario = SCENARIOS[scenario_id]
    return {
        "schema_version": 1,
        "scenario_id": scenario_id,
        "classification": scenario.expected_classification,
        "identified_event_types": list(scenario.required_event_types),
        "containment_actions": list(scenario.containment_actions),
        "recovery_actions": list(scenario.recovery_actions),
        "false_positive_assessment": scenario.false_positive_assessment,
        "analyst_notes": "Synthetic lab answer used only for regression testing.",
    }


def test_expected_fixed_scenarios_are_bundled() -> None:
    assert set(SCENARIOS) == EXPECTED_SCENARIOS


def test_synthetic_datasets_are_owned_and_local_only() -> None:
    forbidden_keys = {"host", "hostname", "ip", "port", "url", "command", "target_path", "share"}
    for scenario_id in SCENARIOS:
        events = load_dataset(scenario_id)
        assert events
        for event in events:
            assert event["project"] == config.PROJECT_NAME
            assert event["scenario_id"] == scenario_id
            assert event["schema_version"] == 1
            assert not (forbidden_keys & set(event))


def test_perfect_answers_score_100() -> None:
    for scenario_id, scenario in SCENARIOS.items():
        result = score_response(scenario, _perfect_response(scenario_id))
        assert result["score"] == 100
        assert result["grade"] == "excellent"


def test_partial_answer_scores_below_full() -> None:
    scenario = SCENARIOS["basic"]
    response = _perfect_response("basic")
    response["recovery_actions"] = []
    result = score_response(scenario, response)
    assert 0 < result["score"] < 100


def test_inconclusive_scenario_penalizes_forced_conclusion() -> None:
    scenario = SCENARIOS["telemetry-gap"]
    response = _perfect_response("telemetry-gap")
    response["classification"] = "simulated_ransomware_activity"
    result = score_response(scenario, response)
    assert result["score"] < 100


def test_prepare_and_score_exercise_stays_under_fixed_lab(isolated_lab: Path) -> None:
    root = prepare_exercise("basic")
    assert root == config.LAB_ROOT / "exercises" / "basic"
    assert (root / "briefing.md").is_file()
    assert (root / "evidence" / "events.jsonl").is_file()
    response_path = root / "analyst-response.json"
    response_path.write_text(json.dumps(_perfect_response("basic"), indent=2) + "\n", encoding="utf-8")
    result = score_exercise("basic")
    assert result["score"] == 100
    assert (root / "score.json").is_file()
    assert (root / "score.html").is_file()
