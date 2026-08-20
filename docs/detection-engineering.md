# Detection engineering

The detection workflow is designed for blue-team practice:

1. Run the lab in a disposable VM.
2. Collect endpoint/file telemetry.
3. Detect known simulator artifacts and burst behavior.
4. Validate that the initiating process and file paths belong to the lab.
5. Reconstruct the simulation timeline.
6. Run verified recovery and confirm SHA-256 matches.
7. Compare endpoint observations with `ransomware_lab/logs/events.jsonl` and
   the generated JSON/HTML run report.

Useful observable classes include rapid sequential file writes, creation of
`.SIMULATED_LOCKED` artifacts, the harmless simulated note, and recovery-related
file restoration. Detection examples live under `detections/`.

The project intentionally provides no detection-bypass or evasion guidance.
