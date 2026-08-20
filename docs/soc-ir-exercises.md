# SOC/IR Exercise Framework

`v0.3.0-lab` adds a synthetic-evidence workflow so analysts can practice triage
without running the reversible encryption simulation at all.

## Fixed scenarios

| Scenario | Learning goal |
| --- | --- |
| `basic` | detect the simulator event chain and choose appropriate containment/recovery |
| `interrupted` | recognize kill-switch containment and verify recovery |
| `recovery-failure` | preserve a conflict and escalate incomplete recovery safely |
| `false-positive` | avoid over-escalating a single lookalike artifact |

Scenario IDs are compiled into the application. The CLI accepts no arbitrary
dataset, response, target, host, path, or command.

## Analyst workflow

1. List scenarios with `python simulator.py --list-scenarios`.
2. Prepare one with `python simulator.py --exercise basic`.
3. Review `ransomware_lab/exercises/basic/briefing.md` and
   `ransomware_lab/exercises/basic/evidence/events.jsonl`.
4. Edit the fixed `analyst-response.json`.
5. Run `python simulator.py --score-exercise basic`.
6. Review `score.json` and `score.html`.

The generated analyst response contains the following categories:

- classification;
- identified event types;
- containment actions;
- recovery actions;
- false-positive assessment;
- free-form analyst notes.

The scoring engine is deterministic and totals 100 points:

- classification: 25;
- evidence identification: 25;
- containment: 20;
- recovery: 20;
- false-positive handling: 10.

## Replay-only mode

`python simulator.py --replay-scenario <scenario>` prints the packaged synthetic
JSONL evidence to stdout. It does not call the encryption simulator and does not
need authorization, a recovery key, a network, or elevated privileges.

## Evidence preservation

Exercise preparation refuses to overwrite an existing non-empty exercise
directory. Scoring only overwrites a prior score artifact when it can identify
that artifact as a SafeRansomSim-Lab score for the same fixed scenario.
Analyst responses and exercise evidence are not removed by simulator cleanup.
