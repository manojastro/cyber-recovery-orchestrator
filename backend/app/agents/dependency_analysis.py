"""Dependency Analysis Agent: graph impact + recovery ordering constraints."""
from __future__ import annotations

from typing import List

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.graph.dependency_graph import build_graph_from_db
from app.util import utcnow


def run(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    affected_names = set(investigation.context.get("affected_assets") or [])
    if not affected_names:
        raise RuntimeError("incident scope must run before dependency analysis")

    result = ctx.call_tool("query_dependency_graph", {"scope": sorted(affected_names)})
    recovery_order: List[str] = result.data["recovery_order"]

    # Independent blast-radius check over the full graph (dependents of seeds).
    graph = build_graph_from_db(session)
    blast_radius = graph.blast_radius(affected_names)
    downstream_unlisted = sorted(blast_radius - affected_names)
    final_scope = sorted(affected_names | blast_radius)

    if downstream_unlisted:
        evidence = add_evidence(
            session, investigation, source="dependency_graph", timestamp=utcnow(),
            fact="blast radius extends incident scope to downstream dependents: "
                 f"{', '.join(downstream_unlisted)}",
            reliability="high", raw_reference="graph:blast_radius")
    else:
        evidence = add_evidence(
            session, investigation, source="dependency_graph", timestamp=utcnow(),
            fact=f"recovery order computed for {len(final_scope)} assets; "
                 "constraints respect typed dependency edges "
                 "(database/identity/storage/config before dependents)",
            reliability="high", raw_reference="graph:recovery_order")

    conclusion = ("Recovery order constraints computed; dependencies restore "
                  f"before dependents: {' -> '.join(recovery_order)}")
    reasoning = ctx.reason("dependency_analysis", conclusion, {
        "asset_count": len(final_scope),
        "recovery_order": recovery_order,
        "downstream_dependents_added": downstream_unlisted,
    })
    decision = add_decision(
        session, investigation, stage="dependency_analysis",
        kind="dependency_analysis",
        decision_text=conclusion, confidence=0.95, evidence_rows=[evidence],
        alternatives=[{"option": "restore in arbitrary operational order",
                       "rejected_for": "violates typed dependencies; services would "
                                       "start against missing databases/identity"}],
        risk_level="high", requires_approval=False,
        payload={"recovery_order": recovery_order,
                 "final_scope": final_scope,
                 "edges_considered": len(result.data["edges"])},
        reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}),
                             "recovery_order": recovery_order,
                             "final_scope": final_scope}
    session.commit()
    return {"recovery_order": recovery_order, "final_scope": final_scope,
            "decision_id": decision.public_id}
