# Architecture

SafeRansomSim-Lab v0.3.0-lab separates safety-critical simulation code from
synthetic SOC/IR training code so each boundary can be reviewed independently.

```text
simulator.py              compatibility CLI entry point
saferansomsim/
  cli.py                  fixed command surface
  config.py               non-configurable lab roots and limits
  safety.py               containment, path and ownership primitives
  manifest.py             disposable-file creation and eligibility
  crypto_demo.py          AES-256-GCM demo and recovery-key handling
  telemetry.py            local JSONL defensive telemetry
  reporting.py            fixed-root JSON/HTML run evidence
  engine.py               simulation, recovery, status and cleanup orchestration
  scenarios.py            compiled synthetic exercise definitions
  exercises.py            fixed-root exercise preparation and replay
  scoring.py              deterministic SOC/IR scoring
  detection_validation.py Detection Pack metadata/syntax validation
datasets/                 static synthetic JSONL exercise evidence
detections/               defensive Sigma, Sysmon and SIEM content
schemas/                  telemetry, report, exercise-response and score schemas
```

Runtime state remains under the repository-local `ransomware_lab/` tree.

- The only file-processing target is `ransomware_lab/test123/`.
- Run reports are written to `ransomware_lab/reports/`.
- Exercise worksheets and evidence are written only to
  `ransomware_lab/exercises/<fixed-scenario-id>/`.
- Bundled datasets are read-only repository content and are selected only by
  compiled scenario ID.

The SOC/IR exercise path is intentionally independent of the reversible
encryption workflow. Analysts can prepare and replay synthetic evidence without
authorization, a demo recovery key, elevated privileges, or network access.

The root `simulator.py` remains intentionally thin so the safety contract can
detect accidental reintroduction of monolithic or hidden functionality.
