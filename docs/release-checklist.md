# Release checklist

Use this checklist before declaring a `v0.x.0-lab` codebase stable.

- [ ] Version, README, and CHANGELOG agree.
- [ ] Ubuntu and Windows safety-test matrix is green.
- [ ] Detection Pack Validation is green.
- [ ] Schema Validation is green.
- [ ] Dependency Audit is green.
- [ ] CodeQL has no unresolved high-severity alerts attributable to the change.
- [ ] Mutation-safety tests cover new safety-critical behavior.
- [ ] Evidence-manifest verification passes for every bundled scenario.
- [ ] No arbitrary target, dataset, host, path, process, or network capability exists.
- [ ] VM-first guidance remains prominent.
- [ ] Release notes describe safety impact and known limitations.
