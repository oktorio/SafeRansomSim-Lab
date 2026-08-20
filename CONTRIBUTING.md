# Contributing

Contributions are welcome when they strengthen containment, defensive detection, SOC/IR learning, testing, documentation, or evidence integrity.

## Non-negotiable safety contract

Do not add arbitrary target/path options, external dataset execution, network scanning or callbacks, process/shell execution, persistence, propagation, credential access, privilege escalation, backup destruction, security-tool disabling, or evasion. Do not add real phishing attachments, macros, exploit delivery, or downloader behavior.

## Development workflow

1. Create a feature branch from `main`.
2. Keep changes narrowly scoped.
3. Install pinned dependencies with `python -m pip install -r requirements.txt`.
4. Run `python -m pytest -q`, `python simulator.py --validate-detections`, and `python simulator.py --validate-schemas`.
5. Confirm evidence-integrity and mutation-safety tests remain green.
6. Open a PR and wait for all required CI checks before merge.

Changes to safety-critical modules should include a regression test that demonstrates the failure mode being prevented.
