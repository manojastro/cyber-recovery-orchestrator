"""Recovery Planner Agent: ordered plan with per-step source snapshot, RTO/RPO
estimates, validation test, risk and rollback option."""
from __future__ import annotations

from typing import Dict, List

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.graph.dependency_graph import build_graph_from_db, recovery_order
from app.models import Action, Asset
from app.util import deterministic_id, utcnow

# modeled execution seconds per action type (local POC planning constants)
RTO_SECONDS = {
    "restore_configuration": 30.0,
    "restore_storage_objects": 60.0,
    "restore_database_snapshot": 120.0,
    "credential_rotation": 20.0,
    "restart_service": 40.0,
}

# asset -> (action_type, tool_name)
ACTION_MAP = {
    "config-store": ("restore_configuration", "restore_configuration"),
    "object-storage": ("restore_storage_objects", "restore_storage_objects"),
    "core-postgres": ("restore_database_snapshot", "restore_database_snapshot"),
}

VALIDATION_TEST = {
    "restore_configuration": "run_integrity_check:configuration",
    "restore_storage_objects": "run_integrity_check:storage",
    "restore_database_snapshot": "run_integrity_check:database",
    "credential_rotation": "authentication_probe",
    "restart_service": "run_service_health_check",
}


def build_plan(session: Session, investigation, clean_snapshot: str,
               scope: List[str]) -> List[dict]:
    """Deterministic plan construction (also used by tests/evaluation directly)."""
    graph = build_graph_from_db(session)
    assets = {a.name: a for a in session.query(Asset).all()}
    order = [name for name in recovery_order(graph, set(scope))]

    steps: List[dict] = []
    seq = 0
    for asset_name in order:
        tier = assets[asset_name].tier if asset_name in assets else 0
        if asset_name == "identity-service":
            plan_items = [("credential_rotation", "rotate_compromised_credentials",
                           asset_name),
                          ("restart_service", "restart_service", asset_name)]
        elif asset_name in ACTION_MAP:
            action_type, tool = ACTION_MAP[asset_name]
            plan_items = [(action_type, tool, asset_name)]
        else:
            plan_items = [("restart_service", "restart_service", asset_name)]

        # storage/db/config restores carry the source snapshot label; restarts do not.
        for action_type, tool, target in plan_items:
            seq += 1
            steps.append({
                "seq": seq,
                "action_type": action_type,
                "tool_name": tool,
                "target_asset": target,
                "tier": tier,
                "source_snapshot_label": (clean_snapshot if action_type in (
                    "restore_database_snapshot", "restore_storage_objects",
                    "restore_configuration") else None),
                "estimated_rto_seconds": RTO_SECONDS[action_type],
                "validation_test": VALIDATION_TEST[action_type],
                "risk_level": "high" if tool.startswith("restore") else "medium",
            })

    # core-postgres and object-storage/config need a service-style restart too?
    # No: restore handlers already return them to running/healthy state.
    return steps


def run(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    clean_snapshot = investigation.context.get("clean_snapshot")
    scope = investigation.context.get("final_scope")
    if not clean_snapshot or not scope:
        raise RuntimeError("recovery point selection must run before planning")

    steps = build_plan(session, investigation, clean_snapshot, scope)
    planned_rto_total = sum(s["estimated_rto_seconds"] for s in steps)
    rpo_achieved = float(investigation.context.get("rpo_achieved_seconds", 0.0))

    # persist actions
    for step in steps:
        session.add(Action(
            investigation_id=investigation.id,
            public_id=deterministic_id(
                "action", investigation.public_id, str(step["seq"])),
            seq=step["seq"], action_type=step["action_type"],
            tool_name=step["tool_name"], target_asset=step["target_asset"],
            tier=step["tier"],
            source_snapshot_label=step["source_snapshot_label"],
            estimated_rto_seconds=step["estimated_rto_seconds"],
            expected_rpo_seconds=rpo_achieved,
            validation_test=step["validation_test"],
            risk_level=step["risk_level"],
            rollback_option="restore pre-recovery lab image captured at "
                            "execution start",
            status="pending"))

    evidence = add_evidence(
        session, investigation, source="recovery_plan", timestamp=utcnow(),
        fact=f"plan generated: {len(steps)} ordered actions across "
             f"{len(scope)} assets from snapshot {clean_snapshot}; "
             f"modeled RTO {planned_rto_total:.0f}s",
        reliability="high", raw_reference="plan")

    conclusion = (f"Ordered recovery plan ready: {len(steps)} actions, source "
                  f"snapshot {clean_snapshot} per restore step, modeled total RTO "
                  f"{planned_rto_total:.0f}s, expected RPO {rpo_achieved:.0f}s. "
                  "Execution requires human approval.")
    reasoning = ctx.reason("recovery_planning", conclusion, {
        "steps": [{"seq": s["seq"], "tool": s["tool_name"],
                   "target": s["target_asset"]} for s in steps],
        "clean_snapshot": clean_snapshot,
        "planned_rto_seconds": planned_rto_total,
        "expected_rpo_seconds": rpo_achieved,
    })
    decision = add_decision(
        session, investigation, stage="recovery_planning", kind="recovery_plan",
        decision_text=conclusion, confidence=0.9, evidence_rows=[evidence],
        alternatives=[{"option": "skip identity credential rotation to save ~20s",
                       "rejected_for": "compromised credentials would re-compromise "
                                       "restored systems"}],
        risk_level="high", requires_approval=True,
        payload={"steps": steps, "planned_rto_seconds": planned_rto_total,
                 "expected_rpo_seconds": rpo_achieved},
        reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}),
                             "planned_rto_seconds": planned_rto_total}
    session.commit()
    return {"steps": steps, "planned_rto_seconds": planned_rto_total,
            "decision_id": decision.public_id}
