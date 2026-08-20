# Architecture

SafeRansomSim-Lab v0.2.0-lab separates safety-critical responsibilities so each
boundary can be reviewed and tested independently.

```text
simulator.py              compatibility CLI entry point
saferansomsim/
  cli.py                  fixed command surface
  config.py               non-configurable lab roots and limits
  safety.py               containment, path and ownership primitives
  manifest.py             disposable-file creation and eligibility
  crypto_demo.py          AES-256-GCM demo and recovery-key handling
  telemetry.py            local JSONL defensive telemetry
  reporting.py            fixed-root JSON/HTML evidence reports
  engine.py               simulation, recovery, status and cleanup orchestration
```

Runtime state remains under the repository-local `ransomware_lab/` tree. The
only file-processing target is `ransomware_lab/test123/`; reports are written to
`ransomware_lab/reports/`.

The root `simulator.py` remains intentionally thin so the safety contract can
detect accidental reintroduction of monolithic or hidden functionality.
