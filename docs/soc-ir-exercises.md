# SOC/IR Exercise Framework

The synthetic-evidence workflow lets analysts practice triage without running the reversible encryption simulation at all. `v0.5.0-lab` expands the fixed scenario set with additional false-positive, noisy-signal, and incomplete-evidence cases.

## Fixed scenarios

| Scenario | Learning goal |
| --- | --- |
| `basic` | detect the simulator event chain and choose appropriate containment/recovery |
| `interrupted` | recognize kill-switch containment and verify recovery |
| `recovery-failure` | preserve a conflict and escalate incomplete recovery safely |
| `false-positive` | avoid over-escalating a single lookalike artifact |
| `benign-backup-burst` | distinguish expected bursty backup/archive writes from impact signals |
| `mixed-signal` | identify the simulator chain while filtering benign concurrent noise |
| `telemetry-gap` | keep the assessment inconclusive when required evidence is missing |

Scenario IDs are compiled into the application. The CLI accepts no arbitrary dataset, response, target, host, path, or command.

## Analyst workflow

1. List scenarios with `python simulator.py --list-scenarios`.
2. Prepare one with `python simulator.py --exercise basic`.
3. Review the fixed briefing and `evidence/events.jsonl`.
4. Verify evidence with `python simulator.py --verify-evidence basic`.
5. Edit the fixed `analyst-response.json`.
6. Run `python simulator.py --score-exercise basic`.
7. Review `score.json` and `score.html`.

The scoring engine remains deterministic at 100 points: classification 25, evidence identification 25, containment 20, recovery 20, and false-positive handling 10.

## Replay-only mode

`python simulator.py --replay-scenario <scenario>` prints packaged synthetic JSONL evidence to stdout. It does not call the encryption simulator and does not need authorization, a recovery key, a network, or elevated privileges.

## Dataset quality gates

Regression tests require every scenario's scoring evidence to exist in its dataset, timestamps to be monotonic, and each dataset to use one consistent synthetic session ID. Schema validation continues to validate every bundled JSONL event.

## Evidence preservation

Exercise preparation refuses to overwrite an existing non-empty exercise directory. Scoring verifies immutable evidence before scoring, then hashes analyst and score artifacts after scoring. Analyst responses and exercise evidence are not removed by simulator cleanup.
