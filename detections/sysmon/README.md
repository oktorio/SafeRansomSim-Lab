# Sysmon observation guide

SafeRansomSim-Lab does not install or modify Sysmon. If Sysmon is already present
in the disposable Windows VM, the following event classes are useful for a
blue-team exercise:

- **Event ID 1 — Process Create:** identify the Python process used to launch the lab.
- **Event ID 11 — File Create:** observe `.SIMULATED_LOCKED` files and
  `SIMULATED_RANSOM_NOTE.txt`.
- **Event ID 23/26 — File Delete:** where enabled, observe deletion of the
  simulator-owned disposable originals during the controlled simulation and
  deletion of locked artifacts during verified recovery.

Scope analysis to the lab directory and the explicit simulator markers. Do not
treat these event IDs alone as proof of ransomware; correlate process, path,
timing, and authorization context.
