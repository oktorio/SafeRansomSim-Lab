# SafeRansomSim-Lab

**Current lab release: `v0.4.0-lab`**

SafeRansomSim-Lab is a deliberately constrained, non-propagating ransomware-behavior simulator and blue-team SOC/IR exercise framework. It prioritizes containment, reversibility, observability, evidence integrity, and defensive learning over offensive realism.

> **NON-PROPAGATING EDUCATIONAL LAB ONLY.** Simulation file operations are limited to disposable files created by the project inside `./ransomware_lab/test123/`.

## Safety boundary

The CLI has no arbitrary target, path, host, share, external dataset, external response-file, command, or remote-execution option. The project intentionally implements no network/C2, persistence, propagation, credential theft, privilege escalation, security-tool disabling, backup destruction, or evasion.

Use a disposable VM, run as a normal non-admin/non-root user, take a snapshot first, and do not mount host drives or shared folders. Synthetic SOC/IR exercises can be used without running encryption at all.

## v0.4 hardening

`v0.4.0-lab` adds engineering and evidence controls around the existing defensive lab:

- pinned direct Python dependencies;
- SHA-pinned GitHub Actions;
- weekly Dependabot updates for pip and GitHub Actions;
- CodeQL scanning;
- dependency vulnerability auditing with `pip-audit`;
- JSON Schema validation for bundled datasets and generated artifact models;
- SHA-256 evidence manifests for SOC/IR exercises;
- evidence verification before scoring and post-score artifact hashing;
- mutation-safety regression tests;
- `SECURITY.md`, `CONTRIBUTING.md`, CODEOWNERS, PR/issue templates, and a release checklist.

## Quick validation

```bash
python -m pip install -r requirements.txt
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
```

List and prepare:

```bash
python simulator.py --list-scenarios
python simulator.py --exercise basic
```

Exercise artifacts are created only under:

```text
ransomware_lab/exercises/<scenario>/
```

A prepared exercise contains synthetic evidence, an analyst worksheet, and `evidence-manifest.json`. Verify evidence before using it:

```bash
python simulator.py --verify-evidence basic
```

Complete `analyst-response.json`, then score:

```bash
python simulator.py --score-exercise basic
```

Scoring refuses to proceed if the immutable exercise evidence fails SHA-256 verification. After scoring, the analyst response and JSON/HTML score artifacts are added to the evidence manifest and verified again.

Analysts can also replay bundled synthetic telemetry without encryption:

```bash
python simulator.py --replay-scenario interrupted
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
saferansomsim/
  cli.py
  config.py
  safety.py
  manifest.py
  crypto_demo.py
  telemetry.py
  reporting.py
  engine.py
  scenarios.py
  exercises.py
  scoring.py
  evidence.py
  detection_validation.py
  schema_validation.py

datasets/           fixed synthetic SOC/IR telemetry
detections/         defensive Detection Pack
schemas/            versioned JSON Schemas
tests/              containment, recovery, evidence, mutation, schema tests
.github/             CI, CodeQL, Dependabot, governance templates
```

See `docs/architecture.md`, `docs/soc-ir-exercises.md`, and `docs/release-checklist.md`.

## CI and supply-chain controls

GitHub Actions runs the safety suite on Ubuntu and Windows with Python 3.11 and 3.12, plus dedicated Detection Pack Validation, Schema Validation, Dependency Audit, and CodeQL jobs. External GitHub Actions are referenced by immutable commit SHA; Dependabot is configured to propose updates rather than relying on moving major-version tags.

## Governance

Security-sensitive findings should follow `SECURITY.md`. Contributions must follow the safety contract in `CONTRIBUTING.md`. Safety-critical changes should include regression or mutation tests proving the guardrail remains enforced.

## Scope limitation

This project intentionally sacrifices offensive realism for containment, reversibility, evidence quality, and defensive training. It is not intended to reproduce or deliver deployable ransomware.
