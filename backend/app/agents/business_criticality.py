"""Business Criticality Agent: minimum viable business (Tier 0 + Tier 1)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.models import Asset
from app.util import utcnow

MVB_MAX_TIER = 1


def run(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    assets = session.query(Asset).order_by(Asset.tier, Asset.name).all()

    tiers: dict = {}
    for tier in sorted({a.tier for a in assets}):
        tiers[str(tier)] = [a.name for a in assets if a.tier == tier]

    mvb = [a.name for a in assets if a.tier <= MVB_MAX_TIER]
    final_scope = investigation.context.get("final_scope") or []
    recovery_scope_mvb_overlap = sorted(set(mvb) & set(final_scope))
    supporting_not_recovered = sorted(
        set(a.name for a in assets if a.tier > MVB_MAX_TIER) - set(final_scope))

    evidence = add_evidence(
        session, investigation, source="criticality_register", timestamp=utcnow(),
        fact=f"minimum viable business set (tier<= {MVB_MAX_TIER}): {', '.join(mvb)}",
        reliability="high", raw_reference="asset_register")

    conclusion = ("Minimum viable business requires all Tier 0 infrastructure and "
                  f"Tier 1 revenue-path services ({len(mvb)} assets); Tier 2 "
                  "reporting/analytics is deferred where unaffected.")
    reasoning = ctx.reason("business_criticality", conclusion, {
        "mvb_assets": mvb,
        "tiers": tiers,
        "deferred": supporting_not_recovered,
    })
    decision = add_decision(
        session, investigation, stage="business_criticality",
        kind="business_criticality",
        decision_text=conclusion, confidence=0.9, evidence_rows=[evidence],
        alternatives=[{"option": "restore everything including Tier 2 before "
                                 "revenue path",
                       "rejected_for": "delays minimum viable business restoration"}],
        risk_level="medium", requires_approval=False,
        payload={"mvb_assets": mvb, "tiers": tiers,
                 "recovery_scope": final_scope},
        reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}),
                             "mvb_assets": mvb, "tier_map": tiers}
    session.commit()
    return {"mvb_assets": mvb, "tiers": tiers, "decision_id": decision.public_id}
