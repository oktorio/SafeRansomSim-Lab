# Detection Pack

This directory contains **defensive, lab-specific detection content** for SafeRansomSim-Lab.

The rules intentionally key on simulator artifacts such as `.SIMULATED_LOCKED` and
`SIMULATED_RANSOM_NOTE.txt`. They are not intended to identify every real-world
ransomware family and they contain no bypass, evasion, persistence, exploitation,
or payload-delivery logic.

## Contents

- `sigma/` — portable Sigma examples for lab artifact creation.
- `sysmon/` — Windows telemetry guidance for observing the simulator.
- `siem/` — example queries for Microsoft Sentinel and Splunk.

Use these detections to practice alert validation, timeline reconstruction,
containment decisions, and recovery verification in a disposable VM.
