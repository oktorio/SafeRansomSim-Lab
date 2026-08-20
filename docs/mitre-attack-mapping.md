# MITRE ATT&CK mapping

SafeRansomSim-Lab uses ATT&CK only as a **defensive learning reference**. The
project deliberately omits capabilities that would make it a deployable
ransomware implementation.

| ATT&CK technique | Lab relationship | Important limitation |
|---|---|---|
| T1486 — Data Encrypted for Impact | Behavioral analogue for reversible encryption of simulator-generated disposable files | Fixed sandbox only; originals are verified/backed up and recovery is built in |
| T1204.002 — User Execution: Malicious File | `--simulate-initial-access` can emit a harmless telemetry event representing a user-execution scenario | No email, attachment, macro, exploit, downloader, or malicious file delivery is implemented |

## Explicitly not implemented

The simulator does not perform credential access, persistence, privilege
escalation, discovery of arbitrary user files, lateral movement, command and
control, exfiltration, backup/shadow-copy destruction, or security-tool evasion.

Do not infer an ATT&CK technique merely because a real ransomware family often
uses it; map only behavior actually represented by the lab.
