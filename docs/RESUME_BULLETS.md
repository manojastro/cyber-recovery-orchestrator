# Resume bullets

Project: Autonomous Cyber Recovery & Business Resilience Orchestrator
(FastAPI, SQLAlchemy 2, networkx, pydantic v2, pytest, Prometheus, Docker)

- Built an agentic cyber-recovery orchestrator that automates incident-to-
  recovery for a simulated ransomware attack (9-stage pipeline: scope, dependency
  blast radius, backup integrity, clean-point selection, diagnosis, criticality,
  planning, risk, validation), selecting a provably clean recovery point that a
  naive latest-snapshot restore would have missed.

- Designed a persisted workflow state machine with a human approval gate and
  defense-in-depth execution control: high-risk restore tools independently
  re-verify APPROVED status at call time inside an audited tool registry;
  every tool call (allowed or refused) is persisted with secret-redacted
  arguments.

- Implemented deterministic recovery ordering via Kahn's algorithm over a typed
  dependency graph (tier + stable tie-break), with post-execution legality
  re-validation; achieved exact match to labeled ground-truth order across both
  evaluation scenarios.

- Shipped an evaluation harness replaying scenarios against labeled ground truth
  (detection, clean point, ordering, RPO bound) scoring 100% on both shipped
  scenarios; achieved RPO of exactly 1800s by threading a single clock reference
  through seeding, snapshot generation and fault injection.

- Delivered full-stack observability and UI: Prometheus metrics endpoint plus a
  dark-theme vanilla-JS SPA visualizing live workflow state, layered dependency
  map, backup integrity chips, plan progress and merged audit trail; containerized
  with Docker Compose behind a single command.

- Grew test suite to 65 passing pytest cases (0 failures) covering detector
  rules, snapshot tampering, agent determinism across runs, state-machine
  transition guards, approval-gate refusals, rollback-on-failed-verification,
  HTTP contract errors, and end-to-end evaluation replays.
