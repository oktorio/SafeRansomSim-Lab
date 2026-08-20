"""Deterministic scoring for fixed SOC/IR exercises."""

from __future__ import annotations

from typing import Any

from .scenarios import Scenario


def response_template(scenario: Scenario) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "scenario_id": scenario.scenario_id,
        "classification": "",
        "identified_event_types": [],
        "containment_actions": [],
        "recovery_actions": [],
        "false_positive_assessment": "",
        "analyst_notes": "",
    }


def _normalized_strings(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item).strip() for item in value if str(item).strip()}


def _fraction_score(actual: set[str], expected: tuple[str, ...], points: int) -> int:
    if not expected:
        return points
    matched = sum(1 for item in expected if item in actual)
    return round(points * matched / len(expected))


def score_response(scenario: Scenario, response: dict[str, Any]) -> dict[str, Any]:
    classification = 25 if response.get("classification") == scenario.expected_classification else 0
    evidence = _fraction_score(
        _normalized_strings(response.get("identified_event_types")),
        scenario.required_event_types,
        25,
    )
    containment = _fraction_score(
        _normalized_strings(response.get("containment_actions")),
        scenario.containment_actions,
        20,
    )
    recovery = _fraction_score(
        _normalized_strings(response.get("recovery_actions")),
        scenario.recovery_actions,
        20,
    )
    false_positive = (
        10
        if response.get("false_positive_assessment") == scenario.false_positive_assessment
        else 0
    )
    total = classification + evidence + containment + recovery + false_positive
    return {
        "schema_version": 1,
        "scenario_id": scenario.scenario_id,
        "score": total,
        "max_score": 100,
        "grade": (
            "excellent" if total >= 90
            else "proficient" if total >= 75
            else "developing" if total >= 60
            else "needs_review"
        ),
        "breakdown": {
            "classification": {"score": classification, "max": 25},
            "evidence_identification": {"score": evidence, "max": 25},
            "containment": {"score": containment, "max": 20},
            "recovery": {"score": recovery, "max": 20},
            "false_positive_handling": {"score": false_positive, "max": 10},
        },
    }
