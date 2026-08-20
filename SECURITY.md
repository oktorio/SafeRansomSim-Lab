# Security Policy

SafeRansomSim-Lab is intentionally constrained to synthetic, local-only defensive training. Security reports should focus on failures of those containment guarantees, supply-chain weaknesses, unsafe overwrite behavior, or evidence-integrity defects.

## Supported version

The current `main` branch and the most recent `v0.x.0-lab` codebase are supported.

## Reporting a vulnerability

Do **not** include real credentials, production data, exploit payloads, or instructions that expand the simulator into deployable ransomware. Use GitHub's private security advisory/reporting feature when available. If private reporting is unavailable, open a minimal issue that states only that a security-sensitive defect exists and avoid publishing exploit details.

High-priority examples include arbitrary-path access, symlink/junction escape, network/process-execution capability, bypass of authorization or kill-switch checks, unsafe cleanup, recovery overwrite, and evidence-manifest bypass.

## Safety boundary

Security fixes must preserve the fixed `ransomware_lab/test123/` target, synthetic datasets, local-only evidence, no network/C2, no persistence/propagation, no credential access, no privilege escalation, and no defense evasion.
