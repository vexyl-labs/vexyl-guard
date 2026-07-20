# AI Runtime Evaluation

Vexyl Guard includes a deterministic regression suite for its public AI runtime
scoring contract. The suite checks whether known benign and risk-labeled
security summaries remain on the intended side of the scoring and intervention
boundaries as the implementation changes.

This is a curated software regression benchmark. Its perfect expected metrics
do not represent real-world detection accuracy, a production false-positive
rate, or a claim that Vexyl Guard detects every attack.

## Corpus

The public corpus is
[`tests/fixtures/evaluation/ai-runtime-evaluation.json`](../../tests/fixtures/evaluation/ai-runtime-evaluation.json).
It currently contains 35 isolated cases:

- 12 benign boundary cases.
- 23 risk cases.
- Coverage for all 22 public defensive attack-pattern identifiers.
- External-content, memory, agent-plan, tool-policy, model, supply-chain,
  identity, inter-agent, orchestration, approval, and oversight boundaries.

Every case contains a short synthetic defensive summary and normalized event
metadata. The fixture validator rejects raw-content fields, URLs, code fences,
private-key markers, redactable sensitive values, and overlong text. The corpus
does not contain runnable exploit code, malware code, full jailbreak payloads,
raw logs, secrets, or step-by-step offensive instructions.

## Isolation

Each case is evaluated against its own temporary SQLite database. The runner
loads only `PUBLIC_SEED_RECORDS`, even when a developer machine has optional
local intelligence files. This prevents runtime history and machine-specific
data from changing the result. Temporary databases are deleted when the run
ends.

The runner prints only case identifiers, labels, score bands, policy outcomes,
and matched public attack identifiers. It does not echo event summaries.

## Metrics

A case is classified as risk when its score is at least 25, the start of the
documented `warn/log` band. The report calculates:

- True positives, true negatives, false positives, and false negatives.
- Precision, recall, specificity, and accuracy.
- Benign intervention rate.
- Critical intervention recall.
- Public attack-pattern coverage.

An intervention is policy exit code `3` or `4`: require approval/policy
verification, quarantine/block the tool action, or block and open an incident.
Cases marked `requires_intervention` must cross that boundary. Benign cases
must not cross it.

The committed thresholds are intentionally strict because every case is a
stable regression contract:

| Metric | Required value |
| --- | ---: |
| Precision | 1.0 |
| Recall | 1.0 |
| Specificity | 1.0 |
| Accuracy | 1.0 |
| Maximum benign intervention rate | 0.0 |
| Critical intervention recall | 1.0 |

## Run

Run the privacy-safe summary:

```bash
python3 -m tests.run_ai_runtime_evaluation
```

Return the machine-readable report:

```bash
python3 -m tests.run_ai_runtime_evaluation --json
```

Run the unit contracts:

```bash
python3 -m unittest tests/test_ai_runtime_evaluation.py -v
```

The pull-request CI workflow, release workflow, and `scripts/prepare-release.sh`
all run the threshold gate. A case mismatch or threshold regression exits
nonzero.

## Maintaining The Suite

Add a case only when it represents a distinct defensive boundary or closes a
known regression gap. Keep the summary synthetic and high level. Set a score
range around the intended action band instead of coupling the case to one exact
score unless the exact score is itself the contract.

When scoring logic changes intentionally:

1. Run the suite and inspect every changed case.
2. Confirm that benign behavior did not gain an intervention and critical
   behavior did not lose one.
3. Review matched attack identifiers and external-content trust levels.
4. Update an expectation only when the policy change is deliberate and
   documented.
5. Add a new fixture for the behavior that motivated the change.

Real-world efficacy requires representative deployment data, operator review,
and separate measurement with appropriate privacy controls. Those results must
not be inferred from this synthetic suite.
