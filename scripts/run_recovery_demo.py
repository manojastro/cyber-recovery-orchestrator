"""End-to-end recovery demo (in-process, no server required):

seed lab -> inject ransomware -> detect -> investigate (scope, dependencies,
backup integrity, clean point, diagnosis, criticality, plan, risk, pre-flight
dry-run) -> HUMAN APPROVAL -> ordered execution -> post-restore verification
-> measured RTO/RPO + audit trail.

Usage:
    python scripts/run_recovery_demo.py [--scenario standard|corrupted_latest]
                                        [--reject]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import get_settings  # noqa: E402
from app.db import init_schema, make_engine, make_session_factory  # noqa: E402
from app.lab.detector import detect_incident  # noqa: E402
from app.lab.incident import inject_ransomware  # noqa: E402
from app.lab.state import seed_lab, wipe_all  # noqa: E402
from app.models import Action, Decision, Evidence, ToolCall  # noqa: E402
from app.util import deterministic_id, utcnow  # noqa: E402
from app.workflow.engine import WorkflowEngine  # noqa: E402

LINE = "=" * 78


def banner(title: str) -> None:
    print()
    print(LINE)
    print(f" {title}")
    print(LINE)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber recovery end-to-end demo")
    parser.add_argument("--scenario", default="standard",
                        choices=["standard", "corrupted_latest"])
    parser.add_argument("--reject", action="store_true",
                        help="reject the approval instead of executing")
    args = parser.parse_args()

    settings = get_settings()
    engine = make_engine(settings.database_url)
    init_schema(engine)
    session = make_session_factory(engine)()

    banner("STEP 1/7 - SEED CYBER RECOVERY LAB (in-process simulation)")
    lab_now = utcnow()
    wipe_all(session)
    summary = seed_lab(session, scenario=args.scenario, now=lab_now)
    print(f"  assets={summary['assets']} dependencies={summary['dependencies']} "
          f"db_records={summary['db_records']} storage_objects={summary['storage_objects']}")
    print(f"  snapshots: {', '.join(summary['snapshots'])}")

    banner("STEP 2/7 - RANSOMWARE INCIDENT INJECTION + DETECTION")
    incident = inject_ransomware(session, scenario=args.scenario, now=lab_now)
    incident = detect_incident(session, incident)
    stats = incident.detection_stats or {}
    print(f"  detected={incident.status == 'open'} rules="
          f"{', '.join(stats.get('fired_rules', []))}")
    print(f"  encrypted_records={stats.get('encrypted_records')} "
          f"deleted_objects={stats.get('deleted_objects')} "
          f"corrupted_configs={stats.get('corrupted_configs')}")
    if incident.status != "open":
        print("FATAL: detector failed to raise incident", file=sys.stderr)
        return 2

    from app.models import Investigation
    investigation = Investigation(
        public_id=deterministic_id("investigation", incident.public_id),
        incident_public_id=incident.public_id, scenario=args.scenario,
        current_state="DETECTED", context={"affected_assets": [], "fault_inject": {}},
        created_at=utcnow(), updated_at=utcnow())
    session.add(investigation)
    session.commit()

    workflow = WorkflowEngine(session, settings)

    banner("STAGE 3/7 - AGENTIC INVESTIGATION (facts from registered tools only)")
    from app.agents.common import StageContext
    probe = StageContext(session=session, investigation=investigation,
                         settings=settings, llm=workflow.llm,
                         registry=workflow.registry)
    timeline = probe.call_tool("query_incident_timeline",
                               {"incident_public_id": incident.public_id})
    affected = set()
    for event in timeline.data["events"]:
        affected.update((event.get("payload") or {}).get("assets", []))
    investigation.context["affected_assets"] = sorted(affected)
    session.commit()
    print(f"  scope agent will see {len(affected)} affected assets")

    for stage_name in ("incident_scope", "dependency_analysis", "backup_integrity",
                       "recovery_point_selection", "diagnosis", "business_criticality",
                       "recovery_planning", "risk_assessment", "pre_flight_validation"):
        started = time.perf_counter()
        output = workflow.run_stage(investigation, stage_name)
        print(f"  [{stage_name}] done in {(time.perf_counter() - started) * 1000:.0f} ms")

    banner("STEP 4/7 - KEY DECISIONS + EVIDENCE")
    decisions = session.query(Decision).filter(
        Decision.investigation_id == investigation.id).order_by(Decision.id).all()
    for decision in decisions:
        print(f"  * {decision.kind} (confidence={decision.confidence:.2f}, "
              f"risk={decision.risk_level})")
        print(f"      {decision.decision[:150]}")
        print(f"      evidence ids: {decision.evidence_ids}")
        for alt in decision.alternatives[:2]:
            print(f"      rejected: {str(alt)[:120]}")

    evidence_rows = session.query(Evidence).filter(
        Evidence.investigation_id == investigation.id).all()
    print(f"  total evidence rows: {len(evidence_rows)}")
    risk_score = investigation.context.get("risk_score")
    risk_band = investigation.context.get("risk_band")
    print(f"  plan risk: {risk_band} ({risk_score}/100)")

    banner("STEP 5/7 - HUMAN APPROVAL GATE (workflow paused)")
    result = workflow.run_to_approval(investigation)
    print(f"  state={investigation.current_state} "
          f"approval={result['approval_public_id']}")
    print("  NOTE: execution is blocked until a human approves. "
          "High-risk restore tools refuse to run without an APPROVED record.")

    if args.reject:
        banner("REJECTION PATH - terminating cleanly (no execution)")
        workflow.reject(investigation, decided_by="demo-operator",
                        note="reject requested via CLI flag")
        print(f"  state={investigation.current_state} "
              f"(actions cancelled; nothing executed)")
        return 0

    banner("STEP 6/7 - APPROVED: ORDERED EXECUTION + POST-RESTORE VERIFICATION")
    approval_obj = workflow.approve(investigation, decided_by="demo-operator",
                                    note="approved via demo script")
    print(f"  approved by {approval_obj.decided_by}; executing...")
    execution = workflow.execute_and_verify(investigation)
    print(f"  final state: {execution['state']} outcome: {execution.get('outcome')}")
    if execution["state"] != "COMPLETED":
        print("  verification FAILED - attempting rollback of pre-recovery image")
        rollback = workflow.rollback(investigation)
        print(f"  rolled back to pre-recovery state ({rollback['restored_rows']} rows)")
        return 3

    banner("STEP 7/7 - OUTCOME METRICS + AUDIT TRAIL")
    from app.models import Outcome as OutcomeModel
    outcome = session.query(OutcomeModel).filter(
        OutcomeModel.investigation_id == investigation.id).order_by(
        OutcomeModel.id.desc()).first()
    print(f"  result                  : {outcome.result}")
    print(f"  RTO modeled / planned   : {outcome.measured_rto_seconds:.0f}s / "
          f"{outcome.planned_rto_seconds:.0f}s")
    print(f"  RPO achieved            : {outcome.measured_rpo_seconds:.0f}s "
          "(time between clean point and compromise start)")
    print(f"  clean point             : {outcome.clean_point_label}")
    print(f"  dependency order correct: {outcome.dependency_order_correct}")

    actions = session.query(Action).filter(
        Action.investigation_id == investigation.id).order_by(Action.seq).all()
    print(f"  executed sequence       : {' -> '.join(a.target_asset for a in actions)}")

    tool_calls = session.query(ToolCall).filter(
        ToolCall.investigation_id == investigation.id).order_by(ToolCall.id).all()
    denied = [t for t in tool_calls if t.status == "denied"]
    print(f"  tool calls audited      : {len(tool_calls)} "
          f"(denied without approval: {len(denied)})")
    print(f"  statuses                : "
          f"{ {s: sum(1 for t in tool_calls if t.status == s) for s in set(t.status for t in tool_calls)} }")

    print()
    print("Demo complete. Start the UI with:")
    print("  python -m uvicorn --app-dir backend app.main:app --port 8011")
    print(f"then open http://localhost:8011/  (llm_mode={settings.llm_mode})")
    session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
