# SafeRansomSim-Lab

**Current lab release: `v0.2.0-lab`**

A deliberately constrained, non-propagating ransomware-behavior simulator for
cybersecurity education, blue-team detection engineering, incident response,
cryptography learning, and recovery testing.

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

Application-level guardrails remain mandatory even inside a VM.

## Safety model

The only file-processing target is hard-coded to:

```text
./ransomware_lab/test123/
```

The CLI intentionally has **no `--target`, `--path`, `--directory`, host, share,
or remote execution option**.

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

Automated **safety-contract tests** fail if prohibited target options or
network/remote-execution/process capability imports are introduced into the
package.

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
│   └── engine.py
├── detections/
│   ├── sigma/
│   ├── sysmon/
│   └── siem/
├── schemas/
├── tests/
└── docs/
```

See [`docs/architecture.md`](docs/architecture.md).

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
```

Run the controlled simulation:

```bash
python simulator.py --simulate
```

Recover:

```bash
python simulator.py --recover
```

Other commands:

```bash
python simulator.py --status
python simulator.py --cleanup
python simulator.py --simulate-initial-access
python simulator.py --version
```

`--simulate-initial-access` emits only a harmless local telemetry event
representing a training scenario. It does not create or deliver an email,
attachment, macro, exploit, downloader, or phishing page.

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

## Detection Pack

The defensive Detection Pack lives under [`detections/`](detections/):

- Sigma examples for `.SIMULATED_LOCKED` and the simulated note;
- Sysmon observation guidance;
- Microsoft Sentinel / Defender example queries;
- Splunk example searches.

The content is intentionally scoped to known simulator artifacts and contains no
bypass or evasion guidance.

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

GitHub Actions runs the suite on:

- Ubuntu / Python 3.11
- Ubuntu / Python 3.12
- Windows / Python 3.11
- Windows / Python 3.12

Tests cover containment, authorization, cross-platform path traversal,
symlink/reparse safety, file/count limits, interrupted recovery, cleanup
ownership verification, reporting, the Detection Pack, and the project safety
contract.

## Scope limitation

This project deliberately sacrifices offensive realism for containment,
reversibility, observability, and defensive learning value. It is not intended
to reproduce a deployable ransomware payload.
