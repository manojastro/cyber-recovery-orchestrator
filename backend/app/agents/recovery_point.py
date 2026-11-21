"""Recovery Point Agent: clean-point selection with explicit justification."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.agents.clean_point import select_clean_point, summarize_scores
from app.agents.common import StageContext, add_decision, add_evidence
from app.util import utcnow


def run(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    incident_started_at = _incident_start(session, investigation)

    result = ctx.call_tool("query_backup_catalog", {})
    candidates = [
        {"label": e["label"], "public_id": e["public_id"], "taken_at": e["taken_at"],
         "status": e["status"], "checksum_ok": e["checksum_ok"],
         "indicator_count": e["indicator_count"],
         "completeness": e.get("completeness", 1.0)}
        for e in result.data["snapshots"]]

    selection = select_clean_point(candidates, incident_started_at)
    chosen = selection["chosen_label"]

    evidence_rows = [
        add_evidence(
            session, investigation, source="clean_point_selection", timestamp=utcnow(),
            fact=f"selected {chosen} (RPO cost "
                 f"{selection['rpo_achieved_seconds']:.0f}s); naive-latest check: "
                 f"{selection['naive_latest_check']['naive_latest_would_reintroduce']}",
            reliability="high", raw_reference=selection["chosen_public_id"]),
        add_evidence(
            session, investigation, source="clean_point_selection", timestamp=utcnow(),
            fact="candidate scoring: " + "; ".join(
                f"{c['label']}={c['score']}({'eligible' if c['eligible'] else 'rejected'})"
                for c in summarize_scores(selection["scored_candidates"])),
            reliability="high", raw_reference="scoring_table"),
    ]

    conclusion = (f"Clean recovery point selected: {chosen}. "
                  f"{selection['rationale_head']}.")
    if selection["naive_latest_check"]["differs_from_chosen"]:
        conclusion += (f" Naive latest ({selection['naive_latest_check']['naive_latest_label']}) "
                       "was rejected: it would reintroduce "
                       f"{selection['naive_latest_check']['naive_latest_would_reintroduce']}.")
    reasoning = ctx.reason("recovery_point_selection", conclusion, {
        "chosen": chosen,
        "rpo_achieved_seconds": selection["rpo_achieved_seconds"],
        "candidates": summarize_scores(selection["scored_candidates"]),
        "naive_latest_check": selection["naive_latest_check"],
    })
    decision = add_decision(
        session, investigation, stage="recovery_point_selection",
        kind="recovery_point_selection",
        decision_text=conclusion,
        confidence=0.92 if selection["risk_band"] == "low" else 0.6,
        evidence_rows=evidence_rows,
        alternatives=[
            {"label": alt["label"], "rejected_for": alt["rejected_for"]}
            for alt in selection["alternatives_rejected"]],
        risk_level="medium", requires_approval=False,
        payload={"selection": {"chosen_label": chosen,
                               "rpo_achieved_seconds":
                                   selection["rpo_achieved_seconds"],
                               "scores": summarize_scores(
                                   selection["scored_candidates"]),
                               "naive_latest_check":
                                   selection["naive_latest_check"]}},
        reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}),
                             "clean_snapshot": chosen,
                             "rpo_achieved_seconds":
                                 selection["rpo_achieved_seconds"]}
    session.commit()
    return {"chosen_label": chosen,
            "rpo_achieved_seconds": selection["rpo_achieved_seconds"],
            "decision_id": decision.public_id}


def _incident_start(session: Session, investigation) -> datetime:
    from app.models import Incident
    incident = session.query(Incident).filter(
        Incident.public_id == investigation.incident_public_id).first()
    if incident is None:
        raise RuntimeError("incident not found for investigation")
    return incident.started_at
