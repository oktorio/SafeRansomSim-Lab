from __future__ import annotations

from datetime import datetime

from saferansomsim.exercises import load_dataset
from saferansomsim.scenarios import SCENARIOS


def test_required_scoring_evidence_is_present_in_each_dataset() -> None:
    for scenario_id, scenario in SCENARIOS.items():
        event_types = {event["event"] for event in load_dataset(scenario_id)}
        assert set(scenario.required_event_types).issubset(event_types)


def test_dataset_timestamps_are_monotonic_and_session_is_consistent() -> None:
    for scenario_id in SCENARIOS:
        events = load_dataset(scenario_id)
        timestamps = [datetime.fromisoformat(event["timestamp"]) for event in events]
        assert timestamps == sorted(timestamps)
        assert len({event["session_id"] for event in events}) == 1


def test_dataset_event_types_are_nonempty_and_explicit() -> None:
    for scenario_id in SCENARIOS:
        for event in load_dataset(scenario_id):
            assert isinstance(event.get("event"), str)
            assert event["event"].strip()
