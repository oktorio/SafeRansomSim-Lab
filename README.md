# SafeRansomSim-Lab

**Current lab release: `v0.3.0-lab`**

A deliberately constrained, non-propagating ransomware-behavior simulator and
blue-team exercise framework for cybersecurity education, detection engineering,
incident response, cryptography learning, and recovery testing.

> **THIS SOFTWARE IS A NON-PROPAGATING EDUCATIONAL RANSOMWARE SIMULATOR. IT IS
> DESIGNED TO OPERATE ONLY ON DISPOSABLE FILES CREATED INSIDE ITS OWN SANDBOX.**

## VM-first safety guidance

Use a **disposable VM** for simulation runs. Recommended controls:

- run as a normal, non-administrator/non-root user;
- take a VM snapshot before the exercise;
- do not mount host drives or shared folders;
- disable host/guest file sharing where practical;
- no network connectivity is required by the simulator;
- run `python simulator.py --dry-run` and `python -m pytest -q` before the first
  `--simulate` execution.

The synthetic SOC/IR exercises can be used without running encryption at all.

## Safety model

The only file-processing target is hard-coded to:

```text
./ransomware_lab/test123/
```

The CLI intentionally has **no arbitrary target, path, directory, host, share,
dataset file, response file, remote execution, or command option**.

Core safeguards include:

- dry-run is the default behavior;
- modification requires an explicit simulation command and exact authorization marker;
- only simulator-generated, manifest-recorded, marker-bearing disposable files are eligible;
- canonical containment checks and symlink/reparse-point rejection;
- traversal rejection for both `/` and `\\` path forms;
- maximum 100 files, 5 MiB per file, 100 MiB total, recursion depth 3;
- kill switch at `ransomware_lab/STOP_SIMULATION`;
- verified local backup before reversible encryption;
- AES-256-GCM through the high-level `cryptography` library;
- SHA-256 verified recovery;
- cleanup removes only cryptographically or hash-verified simulator-owned runtime artifacts;
- no persistence, propagation, lateral movement, privilege escalation, C2,
  credential theft, exfiltration, security-tool disabling, backup destruction,
  or evasion;
- no network activity.

Automated **safety-contract tests** fail if prohibited target/external-input
options or network/remote-execution/process capability imports are introduced.

## Architecture

```text
SafeRansomSim-Lab/
├── simulator.py
├── config.py
├── saferansomsim/
│   ├── cli.py
│   ├── config.py
│   ├── safety.py
│   ├── manifest.py
│   ├── crypto_demo.py
│   ├── telemetry.py
│   ├── reporting.py
│   ├── engine.py
│   ├── scenarios.py
│   ├── exercises.py
│   ├── scoring.py
│   └── detection_validation.py
├── datasets/
│   ├── basic/
│   ├── interrupted/
│   ├── recovery-failure/
│   └── false-positive/
├── detections/
│   ├── sigma/
│   ├── sysmon/
│   └── siem/
├── schemas/
├── tests/
└── docs/
```

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/soc-ir-exercises.md`](docs/soc-ir-exercises.md).

## Quick start

Install:

```bash
python -m pip install -r requirements.txt
```

Create disposable files:

```bash
python simulator.py --setup
```

Create explicit authorization:

```bash
cp ransomware_lab/AUTHORIZED_LAB.example.txt ransomware_lab/AUTHORIZED_LAB.txt
```

PowerShell:

```powershell
Copy-Item ransomware_lab/AUTHORIZED_LAB.example.txt ransomware_lab/AUTHORIZED_LAB.txt
```

Validate first:

```bash
python simulator.py --dry-run
python -m pytest -q
python simulator.py --validate-detections
```

Run the controlled simulation:

```bash
python simulator.py --simulate
```

Recover:

```bash
python simulator.py --recover
```

Other simulation commands:

```bash
python simulator.py --status
python simulator.py --cleanup
python simulator.py --simulate-initial-access
python simulator.py --version
```

`--simulate-initial-access` emits only a harmless local telemetry event
representing a training scenario. It does not create or deliver an email,
attachment, macro, exploit, downloader, or phishing page.

## SOC/IR Exercise Framework

`v0.3.0-lab` adds four fixed, synthetic scenarios:

- `basic`
- `interrupted`
- `recovery-failure`
- `false-positive`

List them:

```bash
python simulator.py --list-scenarios
```

Prepare an exercise:

```bash
python simulator.py --exercise basic
```

This creates only fixed-root exercise artifacts:

```text
ransomware_lab/exercises/basic/
├── LAB_NOTICE.txt
├── briefing.md
├── analyst-response.json
└── evidence/
    └── events.jsonl
```

Edit `analyst-response.json`, then score it:

```bash
python simulator.py --score-exercise basic
```

The score is deterministic out of 100 points:

- classification: 25;
- evidence identification: 25;
- containment: 20;
- recovery: 20;
- false-positive handling: 10.

The framework writes `score.json` and `score.html` in the same fixed scenario
directory. Existing analyst work is not silently overwritten.

### Synthetic telemetry replay

Analysts can train without running file encryption:

```bash
python simulator.py --replay-scenario interrupted
```

Replay mode only prints the bundled JSONL evidence to stdout. It performs no
network activity, process execution, encryption, or target discovery.

See [`datasets/README.md`](datasets/README.md) and
[`docs/soc-ir-exercises.md`](docs/soc-ir-exercises.md).

## JSON and HTML reporting

Each setup, dry-run, simulation, recovery, or cleanup run writes evidence under:

```text
ransomware_lab/reports/
```

Reports are fixed-root, non-networked, and generated as:

```text
run-<session-id>.json
run-<session-id>.html
```

They include run summary, safety-boundary declarations, and telemetry event
counts. Reports are intentionally preserved by `--cleanup` for lab evidence.

Schemas:

- [`schemas/telemetry-v1.schema.json`](schemas/telemetry-v1.schema.json)
- [`schemas/report-v1.schema.json`](schemas/report-v1.schema.json)
- [`schemas/exercise-response-v1.schema.json`](schemas/exercise-response-v1.schema.json)
- [`schemas/exercise-score-v1.schema.json`](schemas/exercise-score-v1.schema.json)

## Detection Pack

The defensive Detection Pack lives under [`detections/`](detections/):

- Sigma examples for `.SIMULATED_LOCKED` and the simulated note;
- Sysmon observation guidance;
- Microsoft Sentinel / Defender example queries;
- Splunk example searches.

Validate it with:

```bash
python simulator.py --validate-detections
```

Validation checks include Sigma YAML parsing, required metadata, UUID IDs,
duplicate IDs, `detection.condition`, ATT&CK tags, and SIEM/Sysmon guidance
presence. GitHub Actions runs this as a dedicated CI job.

The Detection Pack remains intentionally scoped to known simulator artifacts and
contains no bypass or evasion guidance.

See also:

- [`docs/detection-engineering.md`](docs/detection-engineering.md)
- [`docs/mitre-attack-mapping.md`](docs/mitre-attack-mapping.md)
- [`docs/incident-response-exercise.md`](docs/incident-response-exercise.md)

## Cryptographic demonstration

The lab uses AES-256-GCM with a fresh random 96-bit nonce for each disposable
file. A local demo recovery key is written only to:

```text
ransomware_lab/recovery/demo_key.bin
```

No custom cryptographic primitive is implemented. Recovery verifies the
decrypted plaintext against the original manifest SHA-256 before treating it as
successfully restored.

## Testing

```bash
python -m pytest -q
```

GitHub Actions runs the regression suite on:

- Ubuntu / Python 3.11
- Ubuntu / Python 3.12
- Windows / Python 3.11
- Windows / Python 3.12

A separate **Detection Pack Validation** CI job verifies defensive rule metadata
and syntax.

Tests cover containment, authorization, cross-platform path traversal,
symlink/reparse safety, file/count limits, interrupted recovery, cleanup
ownership verification, reporting, synthetic datasets, exercise scoring,
Detection Pack validation, and the project safety contract.

## Scope limitation

This project deliberately sacrifices offensive realism for containment,
reversibility, observability, and defensive learning value. It is not intended
to reproduce a deployable ransomware payload.
