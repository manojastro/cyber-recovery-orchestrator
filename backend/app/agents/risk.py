"""Recovery Risk Agent: deterministic plan risk score + rationale."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.util import utcnow

WEIGHTS = {
    "blast_radius": 0.30,
    "clean_point_age": 0.25,
    "unsafe_snapshots_present": 0.20,
    "rpo_cost": 0.15,
    "rollback_available_relief": 0.10,
}


def compute_risk_score(factors: dict) -> (int, str, str):
    blast = min(factors.get("blast_radius_assets", 0) / 12.0, 1.0)
    age_hours = factors.get("clean_point_age_hours", 0.0)
    age = min(age_hours / 8.0, 1.0)
    unsafe = 0.0 if factors.get("unsafe_snapshots", 0) == 0 else 1.0
    rpo_cost_h = factors.get("rpo_cost_hours", 0.0)
    rpo = min(rpo_cost_h / 2.0, 1.0)
    rollback_relief = 0.0 if factors.get("rollback_available") else 1.0

    score = (WEIGHTS["blast_radius"] * blast * 100
             + WEIGHTS["clean_point_age"] * age * 100
             + WEIGHTS["unsafe_snapshots_present"] * unsafe * 100
             + WEIGHTS["rpo_cost"] * rpo * 100
             - WEIGHTS["rollback_available_relief"] * rollback_relief * 100)
    score = int(max(0, min(100, round(score))))
    band = ("low" if score < 25 else "medium" if score < 50 else
            "high" if score < 75 else "critical")
    rationale = (
        f"score {score}/100 ({band}): blast radius {factors.get('blast_radius_assets')} "
        f"assets; clean point {age_hours:.1f}h old; "
        f"{factors.get('unsafe_snapshots', 0)} compromised snapshot(s) excluded; "
        f"RPO cost {rpo_cost_h:.2f}h; rollback "
        f"{'available' if factors.get('rollback_available') else 'UNAVAILABLE'}")
    return score, band, rationale


def run(ctx: StageContext) -> dict:
    from app.models import RiskAssessment

    session, investigation = ctx.session, ctx.investigation
    clean_snapshot = investigation.context.get("clean_snapshot")
    evaluations = investigation.context.get("backup_evaluations") or []
    scope = investigation.context.get("final_scope") or []
    rpo_seconds = float(investigation.context.get("rpo_achieved_seconds", 0.0))

    snap_age_hours = _snapshot_age_hours(session, investigation, clean_snapshot)
    factors = {
        "blast_radius_assets": len(scope),
        "clean_point_age_hours": snap_age_hours,
        "unsafe_snapshots": sum(1 for e in evaluations if e["status"] == "failed"),
        "rpo_cost_hours": rpo_seconds / 3600.0,
        "rollback_available": True,
    }
    score, band, rationale = compute_risk_score(factors)

    risk_row = RiskAssessment(investigation_id=investigation.id, score=score,
                              band=band, rationale=rationale, factors=factors,
                              created_at=utcnow())
    session.add(risk_row)

    evidence = add_evidence(
        session, investigation, source="risk_model", timestamp=utcnow(),
        fact=f"plan risk assessed at {score}/100 ({band}); weights={WEIGHTS}",
        reliability="high", raw_reference="risk_model")

    conclusion = f"Plan risk is {band} ({score}/100)."
    reasoning = ctx.reason("risk_assessment", conclusion, {"factors": factors,
                                                           "score": score,
                                                           "band": band})
    decision = add_decision(
        session, investigation, stage="risk_assessment", kind="risk_assessment",
        decision_text=conclusion, confidence=0.85, evidence_rows=[evidence],
        alternatives=[], risk_level="high" if band in ("high", "critical") else "medium",
        requires_approval=False, payload={"score": score, "band": band,
                                          "factors": factors},
        reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}),
                             "risk_score": score, "risk_band": band}
    session.commit()
    return {"score": score, "band": band, "rationale": rationale,
            "decision_id": decision.public_id}


def _snapshot_age_hours(session: Session, investigation, label) -> float:
    from app.lab.backups import get_snapshot
    snap = get_snapshot(session, label or "")
    if snap is None:
        return 24.0
    incident = _incident(session, investigation)
    reference = incident.started_at if incident else utcnow()
    delta = reference - snap.taken_at
    return max(delta.total_seconds(), 0.0) / 3600.0


def _incident(session: Session, investigation):
    from app.models import Incident
    return session.query(Incident).filter(
        Incident.public_id == investigation.incident_public_id).first()
