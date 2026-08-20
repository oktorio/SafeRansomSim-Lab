# Changelog

## v0.4.0-lab — 2026-08-20

### Added
- SHA-256 evidence manifests for fixed SOC/IR exercises, including bundled synthetic evidence and defensive Detection Pack files.
- Evidence verification command and pre-score integrity gate.
- Post-score hashing of analyst response and JSON/HTML score artifacts.
- Evidence-manifest JSON Schema.
- Repository-wide JSON Schema validation command and dedicated CI job.
- Mutation-safety regression tests for target-root mutation, arbitrary CLI input attempts, scenario path injection, and evidence tampering.
- CodeQL workflow, dependency audit, Dependabot configuration, and immutable GitHub Action SHA pins.
- `SECURITY.md`, `CONTRIBUTING.md`, CODEOWNERS, pull-request template, issue templates, and release checklist.

### Changed
- Direct Python dependencies are pinned for reproducible CI/lab setup.
- Exercise scoring refuses to score when immutable evidence integrity verification fails.
- Safety contract includes evidence/schema modules and fixed `--verify-evidence` scenario choices.

### Safety
- No arbitrary target, external dataset, host, path, command, process execution, or network capability was introduced.
- The v0.4 milestone is engineering/evidence hardening only; simulation behavior is not made more offensive or deployable.

## v0.3.0-lab — 2026-08-20

### Added
- Fixed SOC/IR exercise framework with `basic`, `interrupted`,
  `recovery-failure`, and `false-positive` scenarios.
- Static synthetic JSONL telemetry datasets that can be replayed without
  running the encryption simulation.
- Fixed-root analyst worksheet generation under
  `ransomware_lab/exercises/<scenario>/`.
- Deterministic 100-point scoring engine with JSON and HTML score output.
- Exercise response and score JSON schemas.
- Detection Pack validator for Sigma YAML metadata, UUID uniqueness,
  ATT&CK tags, SIEM query guidance, and Sysmon guidance.
- Dedicated `Detection Pack Validation` GitHub Actions job.
- CLI commands for listing, preparing, replaying, scoring scenarios, and
  validating detections.

### Safety
- Scenario selection is limited to compiled scenario IDs.
- No arbitrary dataset, response file, target, host, path, or command option
  was introduced.
- Synthetic exercise mode does not require encryption, authorization, network
  access, or elevated privileges.

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
