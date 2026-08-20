"""Fixed, synthetic SOC/IR exercise scenarios.

Scenario identifiers are compiled into the package. No scenario accepts a target
path, host, network location, command, executable, or external data source.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    objective: str
    dataset: str
    expected_classification: str
    required_event_types: tuple[str, ...]
    containment_actions: tuple[str, ...]
    recovery_actions: tuple[str, ...]
    false_positive_assessment: str


SCENARIOS: dict[str, Scenario] = {
    "basic": Scenario(
        scenario_id="basic",
        title="Basic simulated encryption detection",
        objective="Identify a fixed-sandbox encryption pattern, contain it, and verify recovery.",
        dataset="basic/events.jsonl",
        expected_classification="simulated_ransomware_activity",
        required_event_types=(
            "SIMULATION_STARTED",
            "FILE_ENCRYPTION_COMPLETED",
            "RANSOM_NOTE_CREATED",
        ),
        containment_actions=("activate_kill_switch", "preserve_evidence"),
        recovery_actions=("run_recovery", "verify_hashes"),
        false_positive_assessment="not_false_positive",
    ),
    "interrupted": Scenario(
        scenario_id="interrupted",
        title="Interrupted simulation and recovery",
        objective="Recognize a kill-switch interruption and confirm complete hash-verified recovery.",
        dataset="interrupted/events.jsonl",
        expected_classification="contained_simulated_ransomware_activity",
        required_event_types=(
            "SIMULATION_STARTED",
            "FILE_ENCRYPTION_COMPLETED",
            "SIMULATION_STOPPED",
            "FILE_RECOVERED",
            "HASH_VERIFICATION_SUCCESS",
        ),
        containment_actions=("confirm_kill_switch", "preserve_evidence"),
        recovery_actions=("run_recovery", "verify_hashes"),
        false_positive_assessment="not_false_positive",
    ),
    "recovery-failure": Scenario(
        scenario_id="recovery-failure",
        title="Recovery conflict investigation",
        objective="Identify an incomplete recovery caused by an original-path conflict without overwriting evidence.",
        dataset="recovery-failure/events.jsonl",
        expected_classification="recovery_incomplete_requires_review",
        required_event_types=(
            "RECOVERY_STARTED",
            "HASH_VERIFICATION_FAILURE",
        ),
        containment_actions=("preserve_evidence", "preserve_conflicting_file"),
        recovery_actions=("do_not_overwrite_conflict", "escalate_manual_review"),
        false_positive_assessment="not_false_positive",
    ),
    "false-positive": Scenario(
        scenario_id="false-positive",
        title="Benign lookalike triage",
        objective="Avoid over-escalating a single lookalike file event that lacks the simulator event sequence.",
        dataset="false-positive/events.jsonl",
        expected_classification="benign_lookalike",
        required_event_types=(
            "BENIGN_FILE_CREATED",
            "BENIGN_PROCESS_EXITED",
        ),
        containment_actions=("do_not_trigger_emergency_containment", "document_rationale"),
        recovery_actions=("no_recovery_required",),
        false_positive_assessment="false_positive_likely",
    ),
}


def scenario_ids() -> tuple[str, ...]:
    return tuple(SCENARIOS)


def get_scenario(scenario_id: str) -> Scenario:
    try:
        return SCENARIOS[scenario_id]
    except KeyError as exc:
        raise ValueError(f"Unknown scenario id: {scenario_id!r}") from exc
