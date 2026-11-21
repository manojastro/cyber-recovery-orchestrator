"""Validation Agent: pre-flight dry-run and post-restore verification.

Recovery is NOT a success just because restores completed. Post-restore checks:
service health, database integrity (no encryption markers), API probes,
authentication, dependency connectivity, and the end-to-end business
transaction. Any failed check fails the recovery.
"""
from __future__ import annotations

from typing import List, Optional

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.graph.dependency_graph import build_graph_from_db, is_valid_execution_order
from app.lab.business_txn import project_business_transaction
from app.models import Action, Credential, DbRecord, Validation
from app.util import utcnow


def _record(session: Session, investigation, phase: str, name: str,
            target: Optional[str], passed: bool, detail: dict) -> Validation:
    row = Validation(investigation_id=investigation.id, phase=phase, name=name,
                     target=target, passed=passed,
                     detail={"detail": detail}, created_at=utcnow())
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------- dry run

def run_pre_flight(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    clean_snapshot = investigation.context.get("clean_snapshot")
    evaluations = {e["label"]: e for e in
                   (investigation.context.get("backup_evaluations") or [])}
    chosen_eval = evaluations.get(clean_snapshot, {})
    chosen_ok = chosen_eval.get("status") == "verified"

    actions = session.query(Action).filter(
        Action.investigation_id == investigation.id).order_by(Action.seq).all()
    planned_assets = [a.target_asset for a in actions]
    unique_assets = list(dict.fromkeys(planned_assets))

    graph = build_graph_from_db(session)
    order_legal = is_valid_execution_order(unique_assets, graph)
    projection = project_business_transaction(
        chosen_snapshot_ok=chosen_ok,
        planned_assets_recovered=[a.target_asset for a in actions],
        integrity_flags_clean=True)

    checks: List[dict] = []
    checks.append(_check("source_snapshot_verified", clean_snapshot, chosen_ok,
                         {"snapshot": clean_snapshot,
                          "status": chosen_eval.get("status", "unknown")}))
    checks.append(_check("dependency_order_legal", "plan", order_legal,
                         {"sequence": unique_assets}))
    checks.append(_check("projected_business_transaction", "dry-run",
                         projection["predicted_pass"],
                         {"problems": projection["problems"]}))
    for action in actions:
        exists = session.query(DbRecord).filter(
            DbRecord.table_name.isnot(None)).first() is not None
        checks.append(_check(
            f"action_{action.seq}_prerequisites", action.tool_name,
            bool(action.source_snapshot_label in (None, clean_snapshot)) and exists,
            {"target": action.target_asset}))

    all_passed = all(c["passed"] for c in checks)
    for check in checks:
        _record(session, investigation, "dry_run", check["name"],
                check["target"], check["passed"], check["detail"])

    evidence = add_evidence(
        session, investigation, source="pre_flight_dry_run", timestamp=utcnow(),
        fact=("dry run PASSED" if all_passed else
              f"dry run FAILED on: "
              f"{', '.join(c['name'] for c in checks if not c['passed'])}"),
        reliability="high", raw_reference="dry_run")

    conclusion = ("Pre-flight dry-run passed; plan is executable."
                  if all_passed else
                  "Pre-flight dry-run found blocking issues; execution blocked.")
    reasoning = ctx.reason("pre_flight_validation", conclusion,
                           {"checks": [{"name": c["name"], "passed": c["passed"]}
                                       for c in checks]})
    from app.agents.common import add_decision
    decision = add_decision(
        session, investigation, stage="pre_flight_validation",
        kind="pre_flight_validation", decision_text=conclusion,
        confidence=0.9 if all_passed else 0.5,
        evidence_rows=[evidence], alternatives=[], risk_level="medium",
        requires_approval=False, payload={"passed": all_passed, "checks": checks},
        reasoning=reasoning["content"])

    session.commit()
    return {"passed": all_passed, "checks": checks,
            "decision_id": decision.public_id}


# ------------------------------------------------------------- post restore

def run_post_restore(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    fault = (investigation.context or {}).get("fault_inject") or {}
    checks: List[dict] = []

    # 1. service health across every service/identity component
    health = ctx.call_tool("run_service_health_check", {})
    checks.append({"name": "service_health_all_recovered", "target": "services",
                   "passed": bool(health.data.get("healthy")),
                   "detail": health.data.get("checks", [])})

    # 2. database integrity: no encryption markers
    db_integrity = ctx.call_tool("run_integrity_check", {"target": "database"})
    checks.append({"name": "database_integrity_no_markers", "target": "core-postgres",
                   "passed": bool(db_integrity.data.get("clean")),
                   "detail": {"encrypted_markers":
                              db_integrity.data.get("encrypted_markers"),
                              "corrupted_rows":
                              db_integrity.data.get("corrupted_rows")}})

    # 3/4. storage + configuration integrity
    storage_integrity = ctx.call_tool("run_integrity_check", {"target": "storage"})
    checks.append({"name": "storage_integrity", "target": "object-storage",
                   "passed": bool(storage_integrity.data.get("clean")),
                   "detail": storage_integrity.data})
    config_integrity = ctx.call_tool("run_integrity_check", {"target": "configuration"})
    checks.append({"name": "configuration_integrity", "target": "config-store",
                   "passed": bool(config_integrity.data.get("clean")),
                   "detail": config_integrity.data})

    # 5. authentication works: identity running + no active compromised creds
    compromised = session.query(Credential).filter(
        Credential.status == "compromised").count()
    auth_ok = compromised == 0 and _asset_running(session, "identity-service")
    checks.append({"name": "authentication_probe", "target": "identity-service",
                   "passed": auth_ok,
                   "detail": {"active_compromised_credentials": compromised}})

    # 6. dependency connectivity: each service's dependencies running
    connectivity_ok, connectivity_detail = _connectivity_check(session)
    checks.append({"name": "dependency_connectivity", "target": "graph",
                   "passed": connectivity_ok, "detail": connectivity_detail})

    # 7. API functionality probe (storefront reachable, catalog readable)
    api_ok = (_asset_running(session, "web-frontend") and
              session.query(DbRecord).filter(
                  DbRecord.table_name == "products", DbRecord.encrypted.is_(False),
                  DbRecord.deleted.is_(False)).count() > 0)
    checks.append({"name": "api_functionality_probe", "target": "web-frontend",
                   "passed": api_ok, "detail": {"probe": "GET /products via storefront"}})

    # 8. end-to-end business transaction
    if fault.get("post_validation_failure"):
        txn = {"passed": False, "failed_step": None,
               "steps": [{"name": "injected_fault", "passed": False,
                          "detail": "post-validation failure injected for testing"}]}
    else:
        txn_result = ctx.call_tool("run_business_transaction_test", {})
        txn = txn_result.data
    checks.append({"name": "business_transaction_end_to_end", "target": "journey",
                   "passed": bool(txn.get("passed")), "detail": txn})

    all_passed = all(c["passed"] for c in checks)
    for check in checks:
        _record(session, investigation, "post_restore", check["name"],
                check["target"], check["passed"], check["detail"])

    failed_names = [c["name"] for c in checks if not c["passed"]]
    evidence = add_evidence(
        session, investigation, source="post_restore_verification", timestamp=utcnow(),
        fact=("all post-restore checks passed" if all_passed
              else f"post-restore checks FAILED: {', '.join(failed_names)}"),
        reliability="high", raw_reference="verification")

    conclusion = ("Business service verified operational after recovery."
                  if all_passed else
                  f"Post-restore verification failed: {', '.join(failed_names)}. "
                  "Rollback option available.")
    reasoning = ctx.reason("post_restore_verification", conclusion,
                           {"failed_checks": failed_names})
    from app.agents.common import add_decision
    decision = add_decision(
        session, investigation, stage="post_restore_verification",
        kind="verification_verdict", decision_text=conclusion,
        confidence=0.95 if all_passed else 0.99, evidence_rows=[evidence],
        alternatives=[], risk_level="high" if not all_passed else "low",
        requires_approval=False, payload={"passed": all_passed,
                                          "failed_checks": failed_names},
        reasoning=reasoning["content"])

    session.commit()
    return {"passed": all_passed, "failed_checks": failed_names,
            "decision_id": decision.public_id}


# ------------------------------------------------------------- helpers

def _check(name: str, target: Optional[str], passed: bool, detail: dict) -> dict:
    return {"name": name, "target": target, "passed": passed, "detail": detail}


def _asset_running(session: Session, name: str) -> bool:
    from app.models import Asset
    asset = session.query(Asset).filter(Asset.name == name).first()
    return bool(asset and asset.state == "running")


def _connectivity_check(session: Session):
    from app.models import Asset, Dependency
    edges = session.query(Dependency).filter(
        Dependency.dep_type != "SERVICE_CALLS_SERVICE").all()
    problems = []
    states = {a.name: a.state for a in session.query(Asset).all()}
    for edge in edges:
        if edge.from_asset in states and states.get(edge.from_asset) == "running":
            if states.get(edge.to_asset) != "running":
                problems.append(f"{edge.from_asset} -> {edge.to_asset} unavailable")
    detail = {"checked_edges": len(edges), "problems": problems}
    return (len(problems) == 0), detail
