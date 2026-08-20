#!/usr/bin/env python3
"""Compatibility entry point for SafeRansomSim-Lab v0.2.0-lab."""

from saferansomsim.cli import build_parser, main
from saferansomsim.engine import cleanup, dry_run, recover, setup, simulate, status
from saferansomsim.manifest import load_manifest, validate_inventory
from saferansomsim.safety import SafetyError, backup_path, sha256_file, target_path

__all__ = ["SafetyError", "backup_path", "build_parser", "cleanup", "dry_run", "load_manifest", "main", "recover", "setup", "sha256_file", "simulate", "status", "target_path", "validate_inventory"]

if __name__ == "__main__":
    raise SystemExit(main())
