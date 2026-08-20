# SafeRansomSim-Lab

**Current lab release: `v0.5.0-lab`**

SafeRansomSim-Lab is a deliberately constrained, non-propagating ransomware-behavior simulator and blue-team SOC/IR exercise framework. It prioritizes containment, reversibility, observability, evidence integrity, and defensive learning over offensive realism.

> **NON-PROPAGATING EDUCATIONAL LAB ONLY.** Simulation file operations are limited to disposable files created by the project inside `./ransomware_lab/test123/`.

## Safety boundary

The CLI has no arbitrary target, path, host, share, external dataset, external response-file, command, or remote-execution option. The project intentionally implements no network/C2, persistence, propagation, credential theft, privilege escalation, security-tool disabling, backup destruction, or evasion.

Use a disposable VM, run as a normal non-admin/non-root user, take a snapshot first, and do not mount host drives or shared folders. Synthetic SOC/IR exercises can be used without running encryption at all.

## v0.5 detection-content maintenance

`v0.5.0-lab` changes defensive training content and maintenance controls only; simulator behavior is unchanged.

- adds `benign-backup-burst` for bursty-write false-positive discrimination;
- adds `mixed-signal` for separating benign noise from the known simulator chain;
- adds `telemetry-gap` for explicit inconclusive triage when evidence is incomplete;
- adds dataset-quality regression tests for required evidence, timestamp ordering, and session consistency;
- updates the fixed scenario enums used by scoring/evidence schemas;
- updates `pytest` to the current pinned release and adds `pip check` to the cross-platform matrix.

## v0.4 hardening

`v0.4.0-lab` added pinned dependencies, SHA-pinned Actions, Dependabot, CodeQL, `pip-audit`, schema validation, SHA-256 evidence manifests, mutation-safety tests, and project governance files.

## Quick validation

```bash
python -m pip install -r requirements.txt
python -m pip check
python -m pytest -q
python simulator.py --validate-detections
python simulator.py --validate-schemas
```

The default command remains a dry run. A controlled file-transform simulation still requires the fixed sandbox, explicit authorization marker, manifest-owned disposable files, and all containment checks.

## SOC/IR exercises

Bundled scenarios:

```text
basic
interrupted
recovery-failure
false-positive
benign-backup-burst
mixed-signal
telemetry-gap
```

List and prepare:

```bash
python simulator.py --list-scenarios
python simulator.py --exercise telemetry-gap
```

Exercise artifacts are created only under `ransomware_lab/exercises/<scenario>/`. Verify evidence before scoring:

```bash
python simulator.py --verify-evidence telemetry-gap
python simulator.py --score-exercise telemetry-gap
```

Scoring refuses to proceed if immutable exercise evidence fails SHA-256 verification. Analysts can replay bundled synthetic telemetry without encryption:

```bash
python simulator.py --replay-scenario mixed-signal
```

## Simulator commands

```bash
python simulator.py --setup
python simulator.py --dry-run
python simulator.py --simulate
python simulator.py --recover
python simulator.py --status
python simulator.py --cleanup
python simulator.py --simulate-initial-access
python simulator.py --version
```

`--simulate-initial-access` records only a harmless local training telemetry event. It does not create or deliver email, attachments, macros, exploits, downloaders, or phishing pages.

## Detection and schema validation

```bash
python simulator.py --validate-detections
python simulator.py --validate-schemas
```

The Detection Pack includes lab-specific Sigma examples, Sysmon observation guidance, Microsoft Sentinel/Defender examples, and Splunk examples. Schema validation checks all repository schemas, bundled JSONL scenario events, exercise response/score models, report structure, and evidence-manifest structure.

## Architecture

```text
saferansomsim/      fixed-sandbox engine and SOC/IR framework
datasets/           fixed synthetic SOC/IR telemetry
detections/         defensive Detection Pack
schemas/            versioned JSON Schemas
tests/              containment, recovery, evidence, mutation, schema and dataset-quality tests
.github/             CI, CodeQL, Dependabot, governance templates
```

See `docs/architecture.md`, `docs/soc-ir-exercises.md`, and `docs/release-checklist.md`.

## CI and supply-chain controls

GitHub Actions runs the safety suite on Ubuntu and Windows with Python 3.11 and 3.12, plus dedicated Detection Pack Validation, Schema Validation, Dependency Audit, and CodeQL jobs. External Actions remain immutable-SHA pinned; Dependabot proposes updates.

## Governance

Security-sensitive findings should follow `SECURITY.md`. Contributions must follow the safety contract in `CONTRIBUTING.md`. Safety-critical changes should include regression or mutation tests proving the guardrail remains enforced.

## Scope limitation

This project intentionally sacrifices offensive realism for containment, reversibility, evidence quality, and defensive training. It is not intended to reproduce or deliver deployable ransomware.
