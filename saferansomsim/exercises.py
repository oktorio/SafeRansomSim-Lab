"""Fixed-root SOC/IR exercise preparation, replay, scoring, and evidence integrity."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from . import config
from .evidence import record_artifacts, verify_manifest, write_initial_manifest
from .safety import SafetyError, atomic_write, canonical_within, ensure_lab_integrity, reject_link, reject_link_components
from .scenarios import Scenario, get_scenario
from .scoring import response_template, score_response

NOTICE = (
    "THIS IS A CYBERSECURITY LAB EXERCISE USING SYNTHETIC TELEMETRY ONLY.\n"
    "NO REAL VICTIM, HOST, EMAIL PAYLOAD, NETWORK TARGET, OR PRODUCTION DATA IS USED.\n"
)


def _dataset_root() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets"


def _exercise_root() -> Path:
    return config.LAB_ROOT / "exercises"


def _scenario_root(scenario: Scenario) -> Path:
    root = _exercise_root() / scenario.scenario_id
    canonical_within(root, config.LAB_ROOT)
    return root


def _dataset_path(scenario: Scenario) -> Path:
    path = _dataset_root() / scenario.dataset
    canonical_within(path, _dataset_root())
    return path


def load_dataset(scenario_id: str) -> list[dict[str, Any]]:
    scenario = get_scenario(scenario_id)
    path = _dataset_path(scenario)
    if not path.is_file() or path.is_symlink():
        raise SafetyError(f"Bundled synthetic dataset missing or unsafe for scenario: {scenario_id}")
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SafetyError(f"Invalid synthetic dataset JSON at line {number}") from exc
        if not isinstance(event, dict) or event.get("scenario_id") != scenario_id:
            raise SafetyError(f"Synthetic dataset ownership mismatch at line {number}")
        events.append(event)
    if not events:
        raise SafetyError(f"Synthetic dataset is empty: {scenario_id}")
    return events


def _briefing(scenario: Scenario) -> bytes:
    return (
        f"# SOC/IR Exercise — {scenario.title}\n\n"
        f"Scenario ID: `{scenario.scenario_id}`\n\n"
        f"## Objective\n\n{scenario.objective}\n\n"
        "## Rules of engagement\n\n"
        "- The evidence is synthetic and local-only.\n"
        "- Do not execute external commands, payloads, downloads, or network actions.\n"
        "- Base your assessment only on the bundled evidence.\n"
        "- Record your answer in `analyst-response.json`.\n"
        "- Verify `evidence-manifest.json` before relying on evidence.\n"
        "- Use the fixed scenario scoring command after completing the worksheet.\n"
    ).encode("utf-8")


def _write_new(path: Path, data: bytes, root: Path) -> None:
    canonical_within(path, root)
    reject_link_components(path.parent, root)
    if path.exists() or path.is_symlink():
        raise SafetyError(f"Refusing to overwrite existing exercise artifact: {path.name}")
    atomic_write(path, data, root)


def prepare_exercise(scenario_id: str) -> Path:
    scenario = get_scenario(scenario_id)
    ensure_lab_integrity(create=True)
    exercise_root = _exercise_root()
    canonical_within(exercise_root, config.LAB_ROOT)
    reject_link_components(exercise_root, config.LAB_ROOT)
    exercise_root.mkdir(parents=True, exist_ok=True)
    reject_link(exercise_root)

    root = _scenario_root(scenario)
    if root.exists():
        reject_link(root)
        if any(root.iterdir()):
            raise SafetyError(f"Exercise {scenario_id!r} already contains artifacts; refusing to overwrite analyst work.")
    else:
        root.mkdir(parents=False)
    evidence_root = root / "evidence"
    evidence_root.mkdir(parents=False)

    dataset = _dataset_path(scenario).read_bytes()
    _write_new(root / "LAB_NOTICE.txt", NOTICE.encode("utf-8"), root)
    _write_new(root / "briefing.md", _briefing(scenario), root)
    _write_new(evidence_root / "events.jsonl", dataset, root)
    _write_new(
        root / "analyst-response.json",
        (json.dumps(response_template(scenario), indent=2, sort_keys=True) + "\n").encode("utf-8"),
        root,
    )
    write_initial_manifest(root, scenario_id)
    return root


def replay_scenario(scenario_id: str) -> list[dict[str, Any]]:
    return load_dataset(scenario_id)


def verify_exercise_evidence(scenario_id: str) -> dict[str, Any]:
    scenario = get_scenario(scenario_id)
    root = _scenario_root(scenario)
    return verify_manifest(root, scenario_id)


def _load_analyst_response(scenario: Scenario) -> dict[str, Any]:
    root = _scenario_root(scenario)
    response_path = root / "analyst-response.json"
    canonical_within(response_path, root)
    if not response_path.is_file():
        raise SafetyError("Analyst response missing; prepare the exercise first.")
    reject_link(response_path)
    response = json.loads(response_path.read_text(encoding="utf-8"))
    if not isinstance(response, dict) or response.get("scenario_id") != scenario.scenario_id:
        raise SafetyError("Analyst response scenario mismatch.")
    return response


def _owned_score_file(path: Path, scenario_id: str) -> bool:
    if not path.exists():
        return True
    reject_link(path)
    if not path.is_file():
        return False
    if path.suffix == ".json":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(payload, dict) and payload.get("project") == config.PROJECT_NAME and payload.get("scenario_id") == scenario_id
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return f'data-project="{config.PROJECT_NAME}"' in text and f'data-scenario="{scenario_id}"' in text


def _score_html(result: dict[str, Any]) -> bytes:
    rows = "".join(
        f"<tr><th>{html.escape(name)}</th><td>{item['score']} / {item['max']}</td></tr>"
        for name, item in result["breakdown"].items()
    )
    return f"""<!doctype html>
<html lang="en" data-project="{html.escape(config.PROJECT_NAME)}" data-scenario="{html.escape(result['scenario_id'])}">
<head><meta charset="utf-8"><title>{config.PROJECT_NAME} SOC score</title></head>
<body><h1>SOC/IR Exercise Score</h1>
<p>This score applies only to a synthetic SafeRansomSim-Lab exercise.</p>
<p><strong>Evidence integrity before scoring:</strong> {html.escape(result['evidence_integrity'])}</p>
<p><strong>Scenario:</strong> {html.escape(result['scenario_id'])}<br>
<strong>Total:</strong> {result['score']} / {result['max_score']} ({html.escape(result['grade'])})</p>
<table>{rows}</table></body></html>""".encode("utf-8")


def score_exercise(scenario_id: str) -> dict[str, Any]:
    scenario = get_scenario(scenario_id)
    root = _scenario_root(scenario)
    integrity = verify_manifest(root, scenario_id, include_artifacts=False)
    if integrity["status"] != "pass":
        raise SafetyError("Evidence integrity verification failed; refusing to score tampered evidence.")
    response = _load_analyst_response(scenario)
    result = {
        "project": config.PROJECT_NAME,
        "project_version": config.PROJECT_VERSION,
        "evidence_integrity": "pass",
        **score_response(scenario, response),
    }
    json_path = root / "score.json"
    html_path = root / "score.html"
    for path in (json_path, html_path):
        canonical_within(path, root)
        if not _owned_score_file(path, scenario_id):
            raise SafetyError(f"Refusing to overwrite non-owned score artifact: {path.name}")
    atomic_write(json_path, (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"), root)
    atomic_write(html_path, _score_html(result), root)
    record_artifacts(root, scenario_id, [root / "analyst-response.json", json_path, html_path])
    final = verify_manifest(root, scenario_id)
    if final["status"] != "pass":
        raise SafetyError("Post-score evidence manifest verification failed.")
    return result
