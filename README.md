# Autonomous Cyber Recovery & Business Resilience Orchestrator

Project 11 - enterprise agentic AI portfolio (batch 3).

An agentic AI system that orchestrates cyber-recovery from a ransomware incident
end to end: detect the incident, map the dependency blast radius, verify backup
integrity, select a **provably clean** recovery point (not merely the latest one),
plan an ordered recovery, pause for **human approval**, execute restores through
an audited tool registry, and verify business recovery with a live end-to-end
transaction test - then measure RTO/RPO against labeled ground truth.

Everything runs as an in-process simulation lab (services, a PostgreSQL-style
database, MinIO-style object storage, identity and configuration), so the full
pipeline is reproducible offline with zero external infrastructure.

```
DETECTED -> SCOPING -> DEPENDENCY_ANALYSIS -> BACKUP_INTEGRITY ->
RECOVERY_POINT_SELECTION -> DIAGNOSIS -> BUSINESS_CRITICALITY ->
RECOVERY_PLANNING -> RISK_ASSESSMENT -> PRE_FLIGHT_VALIDATION ->
AWAITING_APPROVAL -> APPROVED -> EXECUTING -> VERIFYING -> COMPLETED
                                                     \-> FAILED -> ROLLED_BACK
(reject at the gate terminates cleanly: AWAITING_APPROVAL -> FAILED)
```

## Highlights

- **Clean-point selection beats naive-latest**: the scenario corrupts the newest
  snapshot (BKP-008) after checksum time so its stored hash no longer matches.
  The agent verifies integrity + malicious indicators and picks BKP-007; a naive
  "restore latest" would reintroduce attacker content.
- **Deterministic core, LLM only for reasoning prose**: every fact enters through
  registered tools; recovery decisions are deterministic functions of those facts.
  The mock LLM produces auditable reasoning summaries; swap in any
  OpenAI-compatible endpoint via env vars without touching logic.
- **Enforced workflow state machine** persisted in SQL; illegal transitions raise,
  execution requires `APPROVED`, high-risk restore tools re-check the approval
  inside the tool registry (defense in depth).
- **Full audit trail**: every tool call (allowed or refused) is persisted with
  redacted arguments/results; decisions carry evidence IDs, alternatives
  considered, risk level and confidence.
- **Business-level verification**: post-restore checks include a 7-step live
  transaction probe (authenticate -> load config -> browse -> cart -> checkout ->
  order created).
- **Evaluation harness**: replays scenarios against labeled ground truth
  (`evaluation/ground_truth.json`) and scores detection, clean point, ordering
  legality and RPO bound. Both shipped scenarios score 100%.

## Quickstart

Prereqs: Python 3.11+ on Windows PowerShell (adjust paths for POSIX shells).

```powershell
cd "D:\ai apps dump\claude code project\enterprise-agentic-ai-portfolio-batch-3\11-cyber-recovery-orchestrator"

python -m venv .venv
& ".\.venv\Scripts\pip.exe" install -r backend\requirements.txt

# run the entire incident-to-recovery pipeline in one shot (verified)
& ".\.venv\Scripts\python.exe" scripts\run_recovery_demo.py

# start API + UI
& ".\.venv\Scripts\python.exe" -m uvicorn --app-dir backend app.main:app --port 8011
# open http://localhost:8011/
```

The demo prints each stage, the key decisions with evidence, pauses at the human
approval gate, approves, executes the ordered plan, verifies, and prints final
RTO/RPO plus the audit summary.

### Run the tests

```powershell
& ".\.venv\Scripts\python.exe" -m pytest tests -q
# 65 passed in ~200s (0 failures, 0 errors)
```

### Docker

```powershell
docker compose up --build
# http://localhost:8011/  (SQLite persisted to ./data via volume)
docker compose down        # stop; add -v nothing - data is a bind mount
```

## Step-by-step (instead of the one-shot demo)

```powershell
& ".\.venv\Scripts\python.exe" scripts\seed_lab.py                 # reset + seed lab
& ".\.venv\Scripts\python.exe" scripts\simulate_ransomware_incident.py --seed-first
& ".\.venv\Scripts\python.exe" scripts\run_recovery_demo.py        # investigate + recover
& ".\.venv\Scripts\python.exe" -m simulator status                 # inspect lab state
```

Or drive it over HTTP:

```powershell
$base = "http://localhost:8011"
Invoke-RestMethod -Method Post "$base/api/v1/simulator/seed" -Body '{}' -ContentType "application/json"
$inv = Invoke-RestMethod -Method Post "$base/api/v1/incidents/trigger" -Body '{}' -ContentType "application/json"
Invoke-RestMethod -Method Post "$base/api/v1/investigations/$($inv.investigation_public_id)/run"
$ap = (Invoke-RestMethod "$base/api/v1/approvals") | Where-Object status -eq "pending" | Select-Object -First 1
Invoke-RestMethod -Method Post "$base/api/v1/approvals/$($ap.public_id)/approve" `
  -Body '{"decided_by": "ciso", "note": "approved"}' -ContentType "application/json"
Invoke-RestMethod -Method Post "$base/api/v1/investigations/$($inv.investigation_public_id)/execute"
```

## API surface (all under `/api/v1` unless noted)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/meta`, `/health`, `/readiness` | liveness / DB readiness |
| POST | `/api/v1/simulator/seed` | destructive lab reset + seed |
| GET | `/api/v1/assets`, `/dependencies`, `/backups[/{label}]`, `/tools/list` | lab inventory |
| POST | `/api/v1/incidents/trigger` | inject + detect, create investigation |
| GET | `/api/v1/incidents`, `/incidents/{id}`, `/incidents/{id}/events` | incident views |
| GET | `/api/v1/investigations`, `/investigations/{id}` | list / full bundle |
| POST | `/investigations/{id}/run` `/execute` `/rollback` | advance workflow |
| GET/POST | `/approvals[...]` `/approve` `/reject` | human gate |
| GET | `/evidence`, `/decisions`, `/validations`, `/tool-calls`, `/metrics/summary` | audit + KPIs |
| POST/GET | `/evaluation/run`, `/evaluation/runs`, `/evaluation/ground-truth` | scoring |
| GET | `/metrics` | Prometheus exposition format |
| POST | `/api/v1/debug/faults` | only when `ENABLE_FAULT_INJECTION=true` |

OpenAPI docs: `http://localhost:8011/api/docs`.

## Configuration

Copy `.env.example` to `.env` (every key is optional; defaults are fully offline):
`DATABASE_URL` (SQLite default, PostgreSQL supported via `postgresql+psycopg://`),
`LLM_MODE=mock|openai`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`,
`CORS_ORIGINS`, `LOG_LEVEL`, `ENABLE_FAULT_INJECTION`.

## Project layout

```
backend/app/
  api/          FastAPI routers (meta, simulator, incidents, investigations,
                approvals, misc audit routes, evaluation)
  agents/       one module per investigation stage (+ shared StageContext)
  workflow/     persisted state machine engine
  tools/        ToolRegistry: schemas, HIGH-risk approval gate, audit, redaction
  graph/        networkx dependency graph, blast radius, topological ordering
  lab/          simulation: topology, seeding, backups, integrity, incident,
                detector, business-transaction probe
  evaluation/   ground-truth replay runner
  llm/          provider abstraction (mock + OpenAI-compatible)
frontend/       static dark-theme SPA (vanilla JS, polls the API)
evaluation/     ground_truth.json (labeled expectations per scenario)
scripts/        seed_lab.py, simulate_ransomware_incident.py, run_recovery_demo.py
simulator/      `python -m simulator seed|incident|status`
tests/          65 pytest cases (unit, agent determinism, workflow, API, eval)
docs/           INTERVIEW_GUIDE.md, RESUME_BULLETS.md
```

More detail: [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md),
[EVALUATION.md](EVALUATION.md), [DEMO.md](DEMO.md), [LIMITATIONS.md](LIMITATIONS.md).

## Measured results (from actual runs on this repo)

- Tests: **65 passed / 0 failed / 0 errors** (`pytest tests -q`, ~3m20s).
- Detection: all 4 rules fire (mass_record_encryption, mass_object_deletion,
  config_corruption, credential_compromise); 195 records encrypted, 14 objects
  deleted, 4 configs corrupted.
- Clean point: **BKP-007** selected; BKP-008 rejected (`malicious_indicators`,
  checksum mismatch); BKP-006 rejected (older, higher RPO cost).
- Plan: 10 actions across 9 assets, modeled RTO **470 s**, expected RPO **1800 s**;
  plan risk **48/100 (medium)**.
- Execution: COMPLETED; executed order matches ground truth exactly and is
  dependency-legal; RPO achieved exactly **1800.0 s**.
- Audit: **20 tool calls, all success**, arguments/results redacted and persisted.
- Evaluation: standard and corrupted_latest both **pass** with clean-point
  accuracy 1.0, ordering accuracy 1.0, detection correct, RPO within bound.
