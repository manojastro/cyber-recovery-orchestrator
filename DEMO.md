# Demo walkthrough

One-shot script (verified output below):

```powershell
& ".\.venv\Scripts\python.exe" scripts\run_recovery_demo.py
```

The same flow works over HTTP (`POST /simulator/seed` -> `/incidents/trigger` ->
`/investigations/{id}/run` -> approve -> `/execute`) and in Docker
(`docker compose up --build`, port 8011). The SPA at `http://localhost:8011/`
shows the live state while any of these run.

## Step 1 - Seed the lab

Deterministic topology via uuid5 chains:

```
assets=10 dependencies=17 db_records=210 storage_objects=48
snapshots: BKP-001 ... BKP-008   (hourly, BKP-008 newest)
```

## Step 2 - Inject ransomware + detect

70% of records encrypted, attacker inserts added, objects deleted/encrypted,
configs corrupted, 3 principals compromised. Deterministic detector fires all
four rules:

```
detected=True rules=mass_record_encryption, mass_object_deletion,
                config_corruption, credential_compromise
encrypted_records=195 deleted_objects=14 corrupted_configs=4
```

## Step 3 - Agentic investigation (9 stages, tool facts only)

Each stage ~80-150 ms; scope agent sees 9 affected assets from the event
timeline. Stages: incident_scope, dependency_analysis, backup_integrity,
recovery_point_selection, diagnosis, business_criticality, recovery_planning,
risk_assessment, pre_flight_validation.

## Step 4 - Key decisions with evidence

Nine persisted decisions, each with evidence IDs, confidence, alternatives
rejected. The headline ones:

- **backup_integrity**: "7/8 snapshots verified clean; unsafe: BKP-008;
  naive latest restore target BKP-008 is UNSAFE"
- **recovery_point_selection**: clean point **BKP-007** chosen; rejected:
  `BKP-008 (malicious_indicators)`, `BKP-006 (older than selected clean point)`
- **recovery_plan**: "10 actions, source snapshot BKP-007 per restore step,
  modeled total RTO 470s, expected RPO 1800s. Execution requires human approval."
- **risk_assessment**: plan risk medium (**48/100**)

## Step 5 - Human approval gate

Workflow parks at `AWAITING_APPROVAL`; a pending approval row is created.
High-risk restore tools refuse to run without an APPROVED record even if called
directly. (Run the script's reject variant to see rejection cancel all pending
actions and terminate cleanly.)

## Step 6 - Approved execution + verification

After approval the engine executes the plan through the registry:

```
config-store -> core-postgres -> identity-service(rot+restart) ->
object-storage -> customer-service -> payment-service -> order-service ->
web-frontend -> reporting-service
```

Post-restore verification runs 8 checks including the live 7-step business
transaction (authenticate -> config -> browse -> cart -> checkout -> order
created). Final state **COMPLETED**.

## Step 7 - Outcome metrics + audit

```
result                  : completed
RTO modeled / planned   : 470s / 470s
RPO achieved            : 1800s
clean point             : BKP-007
dependency order correct: True
tool calls audited      : 20 (denied without approval: 0)
statuses                : {'success': 20}
```

## Rollback demo (optional)

With `ENABLE_FAULT_INJECTION=true`, arm a post-restore failure:

```powershell
$env:ENABLE_FAULT_INJECTION = "true"   # then start uvicorn in that shell
Invoke-RestMethod -Method Post "http://localhost:8011/api/v1/debug/faults" `
  -Body '{"investigation_id": "<id>", "fault": "post_validation_failure"}' `
  -ContentType "application/json"
```

Verification fails -> state FAILED -> rollback restores the pre-execution lab
image -> state ROLLED_BACK. Covered by tests
(`tests/test_validation.py`, `tests/test_api.py`) without any manual steps.
