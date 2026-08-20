"""Command-line interface. No arbitrary target path is exposed."""

from __future__ import annotations

import argparse
import json
import sys

from . import config
from .engine import cleanup, dry_run, recover, setup, simulate, status
from .safety import SafetyError


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
        else:
            dry_run()
        return 0
    except (SafetyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SAFETY ABORT: {exc}", file=sys.stderr)
        return 2
