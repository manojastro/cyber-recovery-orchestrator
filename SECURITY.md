# Security posture

This is a portfolio simulation, but the control-plane security patterns are the
ones a production deployment would need. What is enforced, and how:

## Human-in-the-loop approval (defense in depth)

1. **Workflow level**: the state machine cannot reach `EXECUTING` from any
   state except `APPROVED`. `execute_and_verify` raises `InvalidTransition`
   otherwise; over HTTP that maps to 409.
2. **Tool registry level**: every tool marked `risk=HIGH`
   (`restore_database_snapshot`, `restore_storage_objects`,
   `restore_configuration`) re-checks, at call time, that an `APPROVED`
   approval row exists for the investigation. Even if workflow guards were
   bypassed in code, the tool itself refuses and writes an audit row.
3. **Reject path**: rejecting at the gate transitions to `FAILED` with
   outcome `rejected`, cancels pending actions, and any subsequent execute
   attempt is refused.

## Agents are sandboxed by construction

- Agents can only act through the `ToolRegistry`: fixed allow-list of 11 tools
  with JSON-schema validated payloads (type/properties/required/enum/items).
- No shell, subprocess, filesystem, or network primitives exist for agents.
  Unknown tool names, schema violations, and unapproved high-risk calls all
  return structured refusals - never exceptions into agent logic.
- Every call attempt - success, refusal, error - persists a `tool_calls` audit
  row with redacted arguments and truncated results.

## LLM containment

- The LLM produces reasoning summaries only (`llm_mode=mock` default;
  OpenAI-compatible endpoint optional). It never selects tools, never sees raw
  credentials, and its output never feeds decision logic: decisions are
  deterministic functions of tool facts.
- API keys are read from environment only and are never logged; the provider
  logs endpoint/model/mode but redacts auth material.
- Latency/retry telemetry goes to Prometheus counters, not log payloads.

## Secret hygiene

- `app/util.redact_secrets` scrubs values whose keys match
  `(password|secret|token|api_key|authorization|credential)` patterns before
  anything is written to the audit trail or returned in tool results.
- Demo data uses obviously fake principals (`admin-ops`, `svc-payment`);
  no real credentials anywhere in the repo.

## HTTP surface

- CORS restricted to configured origins (default localhost:8011), methods
  limited to GET/POST, credentials disabled.
- Global exception handler returns `{"detail": "internal server error"}` -
  stack traces go to server logs only.
- Request bodies are pydantic-validated; unknown scenario names are 422s.
- Destructive lab routes (`POST /simulator/seed`) are explicit resets of a
  simulation database, clearly labeled as such.
- `POST /api/v1/debug/faults` (fault injection for rollback demos) exists only
  when `ENABLE_FAULT_INJECTION=true`; compose defaults it to false.

## Audit trail

Full chain per investigation: events -> evidence -> hypotheses -> decisions ->
approvals -> actions -> validations -> outcomes -> metric_snapshots -> tool_calls,
all queryable via `/api/v1/evidence`, `/decisions`, `/tool-calls`, etc. Each
decision links evidence IDs, alternatives considered with rejection reasons,
confidence, risk band, and whether approval was required - the replayable story
of "why did the agent do this".

## Known gaps (deliberate, see LIMITATIONS.md)

No authentication/authorization layer (single-operator portfolio service),
SQLite default storage, schema via create_all rather than migrations, and the
lab runs in-process rather than against real infrastructure.
