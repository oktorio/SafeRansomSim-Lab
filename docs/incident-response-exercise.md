# Incident Response Exercise

## Objective

Use SafeRansomSim-Lab to rehearse a contained ransomware-response workflow using only simulator-generated disposable data.

## Preconditions

- Run the lab only on a test workstation or disposable VM.
- Install dependencies from `requirements.txt`.
- Run `python simulator.py --setup`.
- Review the generated manifest and dry-run output.
- Explicitly create `ransomware_lab/AUTHORIZED_LAB.txt` from the supplied example.
- Confirm that no real data has been placed under `ransomware_lab/test123/`.

## Scenario

The exercise assumes a user hypothetically opened a malicious email attachment. The lab does not implement such an attachment; `--simulate-initial-access` records only a harmless telemetry marker before starting the same fixed-sandbox simulation.

## Exercise flow

### Phase 1 - Preparation

1. Record a baseline of processes and filesystem activity.
2. Confirm `python simulator.py --status` reports the expected disposable files.
3. Run `python simulator.py --dry-run`.
4. Verify that the dry run changes no file content.

### Phase 2 - Detection

1. Start endpoint/SIEM telemetry collection.
2. Run either:

```bash
python simulator.py --simulate
```

or:

```bash
python simulator.py --simulate-initial-access
```

3. Identify the first high-confidence signal.
4. Determine which process performed the file changes.
5. Correlate file-write bursts, extension changes, cryptographic behavior, and note creation.

### Phase 3 - Containment decision

At any point before the next file operation, create:

```text
ransomware_lab/STOP_SIMULATION
```

The simulator checks this kill switch before every eligible file and stops further processing when it is present.

This provides a safe way to demonstrate the concept of interrupting ongoing impact without implementing any endpoint-killing or security-tool manipulation capability.

### Phase 4 - Scoping

Use `ransomware_lab/logs/events.jsonl` to answer:

- Which disposable files were discovered?
- Which files were transformed?
- What were their SHA-256 hashes before and after?
- How many bytes were processed?
- When did the activity begin and end?
- Was the kill switch invoked?

### Phase 5 - Recovery

Remove the kill-switch file if it exists, then run:

```bash
python simulator.py --recover
```

Confirm:

- Every encrypted lab file is restored.
- Restored SHA-256 values match the manifest.
- `.SIMULATED_LOCKED` files are removed after successful verification.
- The simulated ransom note is removed after full recovery.

### Phase 6 - Lessons learned

Evaluate:

- Time to first detection.
- Telemetry sources that produced useful evidence.
- Whether a single-signal or multi-signal detection performed better.
- False-positive risks.
- Whether recovery verification was complete.
- Whether the playbook clearly separates containment, eradication, recovery, and post-incident review.

## Suggested evidence package

Retain only non-sensitive lab artifacts needed for the exercise report, such as:

- event timeline
- detection screenshots
- SIEM query results
- hash-verification summary
- lessons learned

Do not use production credentials, production files, or real victim data in this lab.

## Reset

After recovery and evidence collection:

```bash
python simulator.py --cleanup
```

The cleanup command is constrained to fixed simulator runtime paths and preserves the explicit authorization file.
