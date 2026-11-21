# Interview guide

How to talk about this project in 30 seconds, 3 minutes, and deep-dive Q&A.

## Elevator pitch (30s)

"When ransomware hits, the instinctive response - restore the latest backup -
can reintroduce the attacker's foothold, because the latest snapshot may have
been taken after compromise started. I built an agentic orchestrator that runs
the full recovery pipeline: it scopes the blast radius over a typed dependency
graph, verifies every snapshot's integrity and malicious-indicator content,
selects a provably clean recovery point, plans a dependency-legal restore
order, pauses for human approval, executes through an audited tool registry,
and then proves business recovery with a live end-to-end transaction test -
measuring RTO/RPO against labeled ground truth with a 100% evaluation score."

## The demo story (3 min)

1. Seed a deterministic enterprise lab: 10 assets, 17 typed dependencies,
   210 DB records, 48 storage objects, 8 hourly snapshots.
2. Inject ransomware: 195 records encrypted, 14 objects deleted, 4 configs
   corrupted, 3 service credentials compromised. Detector fires all four rules.
3. Nine agent stages investigate using only registered tools; the LLM writes
   reasoning summaries but never makes decisions.
4. The trap: naive-latest says BKP-008. Integrity scan shows BKP-008 carries
   malicious indicators (and in the corrupted_latest scenario its checksum no
   longer matches because the manifest was tampered after hashing). The agent
   selects BKP-007 - one hour older, RPO exactly 1800s.
5. Human gate: workflow parks at AWAITING_APPROVAL. Reject terminates cleanly;
   approve unlocks execution.
6. Ten actions execute in dependency-legal order; post-restore verification
   includes a live login->browse->cart->checkout->order-created probe.
7. Outcome: COMPLETED, modeled RTO 470s, RPO 1800s, 20 audited tool calls.

## Deep-dive Q&A

**Q: Where do agents end and deterministic code begin?**
Agents gather facts via tools and persist decisions; every decision is a pure
function of those facts (scoring formulas, graph algorithms). The LLM only
renders reasoning prose from sorted facts. That's what makes evaluation exact:
I'm verifying logic, not sampling model output.

**Q: How is "restore latest is unsafe" actually enforced?**
Three layers: checksum verification catches post-hoc manifest tampering
(corrupted_latest scenario hashes before tampering); a malicious-indicator scan
flags marker samples inside both scenarios' BKP-008; and clean-point eligibility
requires taken_at before compromise start. Any single layer failing disqualifies
a candidate; scoring prefers recency only among eligible candidates.

**Q: How do you guarantee recovery order correctness?**
Kahn's topological sort with (tier, name) selection gives a deterministic plan.
After execution I re-validate the actual sequence with
`is_valid_execution_order` against the live graph - string-equality against
ground truth AND legality are scored independently in evaluation.

**Q: What stops the AI from doing something destructive without approval?**
Defense in depth: the persisted state machine refuses EXECUTING unless APPROVED;
independently, each HIGH-risk tool checks at call time for an APPROVED row in
the registry; unknown tools, schema violations, and unapproved calls all return
structured refusals that still write audit rows. Tests cover each bypass attempt.

**Q: Why does SQLAlchemy JSON mutation matter here?**
In-place edits to a JSON column (`context["k"] = v`) are invisible to change
tracking, so values like planned_rto_seconds silently vanished across HTTP
request boundaries. Every context update is a full-dict reassignment. Good
interview story about a subtle persistence bug found by tests.

**Q: How would you take this to production?**
Real adapters behind the same tool contracts (pgBackRest/WAL-G restores, S3
versioning APIs, IAM credential rotation), a durable worker queue instead of
in-request execution, Alembic migrations, auth/RBAC + signed approvals,
streamed audit events to append-only storage, and per-environment measured RTO
constants replacing planning estimates.

## Known weak spots - own them

- In-process simulation; modeled RTO constants, not wall-clock measurements.
- No auth on the API surface; approvals are rows not signatures.
- Ground truth covers two scenarios; thresholds hand-tuned to fault magnitudes.
- Rejection maps to FAILED+outcome=rejected rather than a distinct state
  (deliberate; keeps rollback reachable).
