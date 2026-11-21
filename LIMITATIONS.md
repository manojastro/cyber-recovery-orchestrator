# Limitations (honest list)

## Simulation scope

- **In-process lab, not real infrastructure.** The PostgreSQL-style database,
  MinIO-style object storage, identity provider and config service are SQLAlchemy
  tables and flag flips inside one process. Restore tools mutate simulated state;
  they do not touch real systems. Wall-clock RTO is therefore modeled
  (per-action planning constants), not measured against real restore durations.
- **RTO numbers are planned constants.** 470 s total comes from per-action-type
  estimates (restore_configuration 30 s, restore_storage_objects 60 s,
  restore_database_snapshot 120 s, credential_rotation 20 s, restart_service
  40 s). A real deployment would measure these per environment.
- **Fault model is scripted ransomware.** Deterministic injection (70% records,
  40% object versions, etc.) with a fixed compromise window. No polymorphic
  behavior, no partial/rolling attacks, no multi-site scenarios.

## Architecture trade-offs

- **SQLite default.** Fine for a single-operator demo; `DATABASE_URL` accepts
  PostgreSQL (`psycopg`) but that path is exercised only by unit-level engine
  checks, not a full integration run.
- **Schema via `create_all`, no Alembic migrations.** Adding columns means
  deleting the dev database or writing migrations yourself.
- **Static SPA is deliberately framework-free** vanilla JS with polling (~3s).
  No websockets, no optimistic UI, no build step - which also caps how rich the
  UX gets.
- **Synchronous workflow engine.** Stages run sequentially in-request; there is
  no background worker queue or distributed execution. A LangGraph adapter seam
  exists in the engine docstring but the shipped engine is plain Python.

## Security gaps

- **No authentication/authorization.** Anyone who can reach the port can seed,
  approve, and execute. Appropriate for a portfolio lab; unacceptable in
  production without an SSO/RBAC layer in front.
- **Approvals are rows, not signatures.** There is no cryptographic
  non-repudiation, MFA, or dual-control workflow on the approval gate.
- **Audit trail lives in the same DB as the lab data**, so it shares fate with
  the database file; a production system would stream audit events to
  append-only storage.
- **Redaction is key-pattern based**; a secret stored under an unexpected key
  name could slip into persisted tool-call args.

## Evaluation boundaries

- Ground truth covers the two shipped scenarios only; accuracy claims are exact
  on those and say nothing about unseen topologies.
- Detection thresholds are hand-tuned to the injected fault magnitudes.
- The evaluation replays deterministically, so it validates logic, not LLM
  variance; with a real (non-mock) LLM configured, reasoning text would vary
  while decisions stay deterministic by construction.
- Deviation: rejection at the approval gate maps to state `FAILED` with outcome
  `rejected` rather than a distinct `REJECTED` terminal state - kept to avoid a
  dead-end state that cannot roll back cleanly.
