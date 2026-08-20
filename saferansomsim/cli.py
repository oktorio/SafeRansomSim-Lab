"""Command-line interface. No arbitrary target path is exposed."""

from __future__ import annotations

import argparse
import json
import sys

from . import config
from .detection_validation import assert_detection_pack_valid
from .engine import cleanup, dry_run, recover, setup, simulate, status
from .exercises import prepare_exercise, replay_scenario, score_exercise
from .safety import SafetyError
from .scenarios import SCENARIOS, scenario_ids


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe, fixed-sandbox ransomware behavior simulator")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--setup", action="store_true", help="create disposable lab files")
    modes.add_argument("--dry-run", action="store_true", help="show eligible files without modifying test files")
    modes.add_argument("--simulate", action="store_true", help="run controlled fixed-sandbox encryption simulation")
    modes.add_argument("--recover", action="store_true", help="decrypt and SHA-256 verify disposable lab files")
    modes.add_argument("--status", action="store_true", help="show current lab state")
    modes.add_argument("--cleanup", action="store_true", help="remove only verified simulator-owned runtime artifacts")
    modes.add_argument("--simulate-initial-access", action="store_true", help="record a harmless local email-execution telemetry event, then run the fixed sandbox simulation")
    modes.add_argument("--version", action="store_true", help="show project version")
    modes.add_argument("--list-scenarios", action="store_true", help="list bundled synthetic SOC/IR scenarios")
    modes.add_argument("--exercise", choices=scenario_ids(), metavar="SCENARIO", help="prepare a fixed bundled SOC/IR exercise")
    modes.add_argument("--replay-scenario", choices=scenario_ids(), metavar="SCENARIO", help="print bundled synthetic telemetry for a scenario")
    modes.add_argument("--score-exercise", choices=scenario_ids(), metavar="SCENARIO", help="score the fixed analyst-response.json for a prepared scenario")
    modes.add_argument("--validate-detections", action="store_true", help="validate defensive Detection Pack metadata and syntax")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.setup:
            setup()
        elif args.simulate:
            simulate()
        elif args.recover:
            recover()
        elif args.status:
            status()
        elif args.cleanup:
            cleanup()
        elif args.simulate_initial_access:
            simulate(initial_access=True)
        elif args.version:
            print(config.PROJECT_VERSION)
        elif args.list_scenarios:
            for scenario in SCENARIOS.values():
                print(f"{scenario.scenario_id}: {scenario.title}")
        elif args.exercise:
            root = prepare_exercise(args.exercise)
            print(f"Prepared synthetic exercise: {root}")
        elif args.replay_scenario:
            for event in replay_scenario(args.replay_scenario):
                print(json.dumps(event, sort_keys=True))
        elif args.score_exercise:
            result = score_exercise(args.score_exercise)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.validate_detections:
            print(json.dumps(assert_detection_pack_valid(), indent=2, sort_keys=True))
        else:
            dry_run()
        return 0
    except (SafetyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SAFETY ABORT: {exc}", file=sys.stderr)
        return 2
