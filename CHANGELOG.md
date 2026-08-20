# Changelog

## v0.2.0-lab — 2026-08-20

### Added
- Modular `saferansomsim` package with separated safety, manifest, cryptography,
  telemetry, reporting, engine, and CLI responsibilities.
- Safety-contract tests that prevent arbitrary target options and prohibited
  network/remote-execution/process capability imports.
- JSON and standalone HTML run reports under `ransomware_lab/reports/`.
- Telemetry and report JSON schemas.
- Defensive Detection Pack with Sigma, Sysmon observation guidance, Microsoft
  Sentinel examples, and Splunk examples.
- Explicit MITRE ATT&CK defensive mapping.
- VM-first execution guidance.

### Changed
- Root `simulator.py` is now a thin compatibility entry point.
- Path validation now rejects traversal written with either `/` or `\\`
  regardless of host operating system.
- Cleanup also checks the recovery directory for unknown runtime artifacts and
  preserves reports as evidence.
