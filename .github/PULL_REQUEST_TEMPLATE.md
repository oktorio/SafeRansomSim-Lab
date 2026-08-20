## Summary

Describe the defensive or safety improvement.

## Safety contract

- [ ] No arbitrary target/path/host/share/external dataset capability added.
- [ ] No network, process execution, persistence, propagation, credential access, privilege escalation, backup destruction, or evasion added.
- [ ] Existing fixed-sandbox and ownership checks remain intact.

## Validation

- [ ] `python -m pytest -q`
- [ ] `python simulator.py --validate-detections`
- [ ] `python simulator.py --validate-schemas`
- [ ] Dependency audit / CodeQL reviewed where applicable.

## Evidence

Explain any new regression or mutation test and the safety invariant it protects.
