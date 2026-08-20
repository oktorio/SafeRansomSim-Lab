# Detection Engineering

This document focuses only on defensive observation and detection opportunities produced by the simulator.

## Observable behaviors

During a controlled simulation, defenders can look for correlated local filesystem signals such as:

- A burst of sequential reads followed by writes.
- Creation of files with the `.SIMULATED_LOCKED` suffix.
- Sudden entropy increase in simulator-generated files.
- Creation of `SIMULATED_RANSOM_NOTE.txt`.
- Repeated cryptographic-library usage in a short period.
- Rapid rename/delete/create behavior against multiple files under one directory.
- A process touching many files whose extensions differ from the process's normal baseline.

The lab itself also writes structured JSONL telemetry to `ransomware_lab/logs/events.jsonl`.

## Example event sequence

```text
AUTHORIZATION_VERIFIED
SIMULATION_STARTED
FILE_ENCRYPTION_STARTED
FILE_ENCRYPTION_COMPLETED
FILE_ENCRYPTION_STARTED
FILE_ENCRYPTION_COMPLETED
RANSOM_NOTE_CREATED
```

For the harmless initial-access simulation, the sequence additionally includes:

```text
SIMULATED_EMAIL_ATTACHMENT_EXECUTION
```

## Defensive correlation concepts

### Mass file modification

Conceptual pseudocode:

```text
IF one process modifies > N distinct files
WITHIN a short time window
AND file-write rate is materially above its historical baseline
THEN raise a ransomware-behavior investigation signal
```

### Extension-change burst

```text
IF one process creates many files with a new/common suffix
AND corresponding source files disappear or are renamed
WITHIN the same directory tree
THEN correlate as a possible mass-encryption pattern
```

### Ransom-note-like artifact

```text
IF a newly created text file contains language indicating files are inaccessible
AND the same process recently performed high-volume file modifications
THEN increase the incident score
```

### Multi-signal correlation

A stronger defensive rule should combine several weak indicators rather than rely on a single filename or extension:

```text
score = 0
IF rapid_file_modification: score += 1
IF entropy_shift: score += 1
IF extension_burst: score += 1
IF note_creation: score += 1
IF unusual_crypto_api_activity: score += 1

IF score >= defensive_threshold:
    generate investigation alert
```

## Telemetry fields produced by the lab

Events may contain:

- timestamp
- session ID
- event type
- source file
- destination file
- SHA-256 before/after
- bytes processed
- elapsed time
- success/failure
- safety-validation result

These fields can be ingested into a SIEM or analyzed locally for blue-team exercises.

## Exercise ideas

1. Establish a clean filesystem/process baseline.
2. Run `--dry-run` and record that no content changes occur.
3. Run the controlled simulation.
4. Compare endpoint telemetry before and during the simulation.
5. Build a multi-signal alert around the observed behavior.
6. Run `--recover` and confirm the restoration sequence.
7. Evaluate false positives against legitimate bulk-file workloads.

## Scope

This document intentionally does not include detection bypass, evasion, obfuscation, or methods for suppressing endpoint telemetry.
