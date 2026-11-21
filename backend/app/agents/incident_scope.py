"""Incident Scope Agent: affected assets derived from the event timeline."""
from __future__ import annotations

from typing import Dict, List

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.models import Asset, Event


def run(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    incident_public_id = investigation.incident_public_id

    timeline = ctx.call_tool("query_incident_timeline",
                             {"incident_public_id": incident_public_id})
    events: List[dict] = timeline.data.get("events", [])

    affected: Dict[str, dict] = {}
    evidence_rows = []
    for event in sorted(events, key=lambda e: e["ts"]):
        for name in (event.get("payload") or {}).get("assets", []):
            if name not in affected:
                asset = session.query(Asset).filter(Asset.name == name).first()
                if asset is None:
                    continue
                affected[name] = {
                    "name": asset.name, "asset_type": asset.asset_type,
                    "tier": asset.tier,
                    "reason": f"referenced by {event['event_type']} at {event['ts']}",
                }
        if event.get("severity") == "critical":
            evidence_rows.append(add_evidence(
                session, investigation, source="event_timeline",
                timestamp=event["ts"], fact=f"{event['event_type']}: {event['message']}",
                reliability="high", raw_reference=event["public_id"]))

    ordered_assets = [affected[name] for name in sorted(affected)]
    conclusion = (f"Incident scope: {len(ordered_assets)} assets affected "
                  f"({', '.join(a['name'] for a in ordered_assets)})")
    reasoning = ctx.reason("incident_scope", conclusion, {
        "affected_asset_count": len(ordered_assets),
        "affected_assets": [a["name"] for a in ordered_assets],
        "timeline_events": len(events),
    })

    decision = add_decision(
        session, investigation, stage="incident_scope", kind="incident_scope",
        decision_text=conclusion, confidence=0.9, evidence_rows=evidence_rows,
        alternatives=[{"option": "treat only degraded services as affected",
                       "rejected_for": "data-plane corruption spans storage/config/identity"}],
        risk_level="high", requires_approval=False,
        payload={"affected_assets": ordered_assets}, reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}),
                             "affected_assets": [a["name"] for a in ordered_assets]}
    session.commit()
    return {"affected_assets": ordered_assets, "timeline_events": len(events),
            "decision_id": decision.public_id}
