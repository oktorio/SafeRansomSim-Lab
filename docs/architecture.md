# Architecture

## Purpose

SafeRansomSim-Lab is a deliberately constrained local simulator for observing ransomware-like filesystem behavior without implementing a deployable ransomware capability.

## Trust boundary

The only file-processing target is compiled into the program as:

```text
<repository>/ransomware_lab/test123/
```

There is no CLI parameter, environment variable, configuration file, or API for selecting another target.

## Components

```text
simulator.py
  |
  +-- safety validation
  |     +-- authorization marker
  |     +-- canonical-path containment
  |     +-- symlink/reparse rejection
  |     +-- manifest ownership
  |     +-- marker/hash validation
  |     +-- file/size/depth limits
  |     +-- kill switch
  |
  +-- disposable test data
  |     `-- ransomware_lab/test123/
  |
  +-- verified local backup
  |     `-- ransomware_lab/backups/
  |
  +-- AES-256-GCM demonstration
  |     `-- ransomware_lab/recovery/demo_key.bin
  |
  +-- structured telemetry
  |     `-- ransomware_lab/logs/events.jsonl
  |
  `-- recovery + SHA-256 verification
```

## Safety invariants

A file is eligible for simulated encryption only when all of the following are true:

1. Its relative path comes from the simulator-generated manifest.
2. The relative path is not absolute, network-based, drive-qualified, or traversal-based.
3. The path canonically resolves inside `test123`.
4. No symlink/reparse point is encountered.
5. The file carries the simulator marker.
6. Its current SHA-256 and size match the manifest.
7. Per-file, aggregate-data, file-count, and recursion-depth limits are satisfied.
8. A verified backup is created before the disposable original is removed.

## Encryption format

Each simulator-generated locked file has this conceptual layout:

```text
SAFERSIM1 | 12-byte random nonce | AES-GCM ciphertext+authentication tag
```

The relative manifest path is supplied as AES-GCM additional authenticated data (AAD), binding the ciphertext to its expected lab filename.

The key is a new random 256-bit AES key for each simulation session. The local recovery-key file contains a human-readable lab label followed by the Base64-encoded key.

## Initial-access simulation

`--simulate-initial-access` does not create an email, macro, exploit, downloader, or attachment. It records a `SIMULATED_EMAIL_ATTACHMENT_EXECUTION` event and then runs the same local constrained simulation.

## Explicitly excluded capability

The project does not implement networking, propagation, remote execution, credential theft, persistence, privilege escalation, defense evasion, backup/shadow-copy deletion, exfiltration, C2, process injection, or destructive disk behavior.
