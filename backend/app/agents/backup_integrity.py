"""Backup Integrity Agent: checksum verification + malicious-indicator scan."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.util import utcnow


def run(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    result = ctx.call_tool("query_backup_catalog", {})
    evaluations = result.data["snapshots"]

    failed = [e for e in evaluations if e["status"] == "failed"]
    verified = [e for e in evaluations if e["status"] == "verified"]

    evidence_rows = []
    for evaluation in failed:
        reasons = ", ".join(evaluation["reasons"])
        markers = ", ".join(sorted({f["marker"] for f in evaluation["findings"]})) or "none"
        evidence_rows.append(add_evidence(
            session, investigation, source="backup_integrity_scan",
            timestamp=utcnow(),
            fact=f"snapshot {evaluation['label']} FAILED verification ({reasons}); "
                 f"indicators={evaluation['indicator_count']} [{markers}]",
            reliability="high",
            raw_reference=evaluation["public_id"]))
    if not failed:
        evidence_rows.append(add_evidence(
            session, investigation, source="backup_integrity_scan", timestamp=utcnow(),
            fact="all snapshots passed checksum + indicator scans",
            reliability="high", raw_reference="backup_catalog"))

    latest_label = evaluations[0]["label"] if evaluations else None
    conclusion = (f"{len(verified)}/{len(evaluations)} snapshots verified clean; "
                  f"unsafe: {', '.join(e['label'] for e in failed) or 'none'}; "
                  f"naive latest restore target {latest_label} is "
                  f"{'UNSAFE' if any(e['label'] == latest_label for e in failed) else 'safe so far'}")
    reasoning = ctx.reason("backup_integrity", conclusion, {
        "total_snapshots": len(evaluations),
        "verified": [e["label"] for e in verified],
        "failed": [{"label": e["label"], "reasons": e["reasons"]} for e in failed],
    })
    decision = add_decision(
        session, investigation, stage="backup_integrity", kind="backup_integrity",
        decision_text=conclusion, confidence=0.95,
        evidence_rows=evidence_rows,
        alternatives=[{"option": f"restore from naive latest snapshot {latest_label}",
                       "rejected_for": "integrity scan shows it is compromised or corrupt"}],
        risk_level="medium", requires_approval=False,
        payload={"evaluations": evaluations},
        reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}), "backup_evaluations": [
        {"label": e["label"], "status": e["status"],
         "checksum_ok": e["checksum_ok"],
         "indicator_count": e["indicator_count"]}
        for e in evaluations]}
    session.commit()
    return {"evaluations": evaluations, "decision_id": decision.public_id}
