# Evaluation

## Method

`backend/app/evaluation/runner.py` replays a full scenario (seed -> inject ->
detect -> 9 agent stages -> approval -> execute -> verify) against the labeled
expectations in `evaluation/ground_truth.json`, then scores four axes:

| Score | Definition |
|---|---|
| `detection_correctness` | detector raised an open incident exactly when truth expects it |
| `clean_point_accuracy` | selected snapshot label equals labeled clean snapshot |
| `ordering_accuracy` | executed action sequence matches expected order AND passes dependency-legality validation |
| `rpo_bound_satisfied` | measured RPO <= labeled bound |

An `EvaluationRun` row persists every replay with pass/fail flags, accuracies,
achieved RTO/RPO and the full truth-vs-observed payload. The run "passes" only
if all four scores are true AND execution reached `COMPLETED`.

## Ground truth (labeled per scenario)

Both scenarios share: clean snapshot **BKP-007**, unsafe snapshots
**[BKP-008]**, RPO bound **1800 s**, and the same expected recovery order:

```
config-store -> core-postgres -> identity-service -> object-storage ->
customer-service -> payment-service -> order-service -> web-frontend ->
reporting-service
```

Scenario differences: in `corrupted_latest`, BKP-008 additionally fails checksum
verification (manifest tampered after hashing), making even an integrity-only
naive check fail - the malicious-indicator scan is what distinguishes BKP-007 as
safe in both cases.

## Measured results

From `pytest tests/test_evaluation.py -q` and `POST /api/v1/evaluation/run`
on this repo (both scenarios):

```
scenario         passed  detection  clean_point  ordering  rpo_bound  achieved_rpo
standard         True    True       1.0          1.0       True       1800.0 s
corrupted_latest True    True       1.0          1.0       True       1800.0 s
```

- RPO achieved is exactly 1800.0 s because one clock reference (`lab_now`) is
  threaded through seeding, snapshot generation and incident injection -
  snapshots sit at whole hours before T0, compromise starts 90 minutes before
  T0, so clean point to compromise start is exactly 30 minutes.
- Naive-latest guard: tests assert BKP-008 is never selected in either
  scenario (`tests/test_evaluation.py::test_naive_latest_snapshot_never_selected`).
- Ordering legality is validated independently of string equality via
  `is_valid_execution_order` over the live graph.

## Reproduce

```powershell
& ".\.venv\Scripts\python.exe" -m pytest tests\test_evaluation.py -q
# 7 passed (2 scenario replays + naive-latest + RPO + persistence + error path)

# or through the running API:
# POST /api/v1/evaluation/run {"scenario": "corrupted_latest"}
# GET  /api/v1/evaluation/runs
# GET  /api/v1/evaluation/ground-truth
```

## Why deterministic scoring matters

Because decisions are deterministic functions of tool facts, evaluation is not
sampling LLM behavior - it verifies pipeline logic. Any regression (ordering,
scoring weights, eligibility rules) flips a score from 1.0 and fails CI. When an
assertion failed during development, the fix was always in logic or ground
truth bookkeeping, never by loosening assertions.
