# Synthetic telemetry datasets

These datasets are static, local-only training evidence for the SafeRansomSim-Lab SOC/IR exercise framework. They are not captured from a victim, production host, email system, endpoint, or network.

Bundled scenarios:

- `basic` — a small simulated encryption sequence and simulated ransom note.
- `interrupted` — one simulated file operation followed by kill-switch containment and successful recovery telemetry.
- `recovery-failure` — a recovery attempt that preserves an original-path conflict.
- `false-positive` — a benign lookalike file event without the simulator event chain.
- `benign-backup-burst` — bursty benign backup/archive activity for false-positive discrimination.
- `mixed-signal` — benign archive noise mixed with the known simulator event sequence.
- `telemetry-gap` — incomplete evidence that should remain inconclusive pending more telemetry.

Every event includes a `scenario_id`. The replay command only prints these bundled JSONL records; it does not execute processes, contact a network, or modify files.
