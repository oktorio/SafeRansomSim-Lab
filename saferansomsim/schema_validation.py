"""Repository schema validation for bundled synthetic defensive artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from . import config
from .scenarios import SCENARIOS
from .scoring import response_template, score_response

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = PROJECT_ROOT / "schemas"
DATASET_ROOT = PROJECT_ROOT / "datasets"


def _perfect_response(scenario: Any) -> dict[str, Any]:
    response = response_template(scenario)
    response.update({
        "classification": scenario.expected_classification,
        "identified_event_types": list(scenario.required_event_types),
        "containment_actions": list(scenario.containment_actions),
        "recovery_actions": list(scenario.recovery_actions),
        "false_positive_assessment": scenario.false_positive_assessment,
        "analyst_notes": "Synthetic schema validation fixture.",
    })
    return response


def assert_repository_schemas_valid() -> dict[str, int]:
    schemas: dict[str, dict[str, Any]] = {}
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema

    telemetry_validator = Draft202012Validator(schemas["telemetry-v1.schema.json"])
    response_validator = Draft202012Validator(schemas["exercise-response-v1.schema.json"])
    score_validator = Draft202012Validator(schemas["exercise-score-v1.schema.json"])
    report_validator = Draft202012Validator(schemas["report-v1.schema.json"])
    evidence_validator = Draft202012Validator(schemas["evidence-manifest-v1.schema.json"])

    dataset_events = 0
    for scenario in SCENARIOS.values():
        path = DATASET_ROOT / scenario.dataset
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            telemetry_validator.validate(event)
            if event.get("scenario_id") != scenario.scenario_id:
                raise ValueError(f"Scenario ownership mismatch in {path}")
            dataset_events += 1

        response = _perfect_response(scenario)
        response_validator.validate(response)
        score = {"project": config.PROJECT_NAME, "project_version": config.PROJECT_VERSION, **score_response(scenario, response)}
        score_validator.validate(score)

    report_validator.validate({
        "schema_version": 1,
        "project": config.PROJECT_NAME,
        "project_version": config.PROJECT_VERSION,
        "generated_at": "2026-08-20T00:00:00+00:00",
        "session_id": "0" * 32,
        "operation": "schema_validation",
        "safety_boundary": {},
        "summary": {},
        "telemetry": {},
    })
    evidence_validator.validate({
        "schema_version": 1,
        "project": config.PROJECT_NAME,
        "project_version": config.PROJECT_VERSION,
        "scenario_id": "basic",
        "generated_at": "2026-08-20T00:00:00+00:00",
        "evidence": [{"scope": "exercise", "path": "evidence/events.jsonl", "sha256": "0" * 64, "size": 1}],
        "artifacts": [],
    })
    return {"schemas": len(schemas), "dataset_events": dataset_events, "scenarios": len(SCENARIOS)}
