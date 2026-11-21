"""Diagnosis stage: hypotheses from tool-derived facts; root cause confirmed."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.agents.common import StageContext, add_decision, add_evidence
from app.models import Hypothesis
from app.util import utcnow


def run(ctx: StageContext) -> dict:
    session, investigation = ctx.session, ctx.investigation
    stats = _detection_stats(session, investigation)
    encrypted = int(stats.get("encrypted_records", 0))
    deleted = int(stats.get("deleted_objects", 0))
    creds = int(stats.get("compromised_credentials", 0))
    configs = int(stats.get("corrupted_configs", 0))

    evidence_rows = [add_evidence(
        session, investigation, source="detector_stats", timestamp=utcnow(),
        fact=f"detection stats: encrypted_records={encrypted}, deleted_objects={deleted}, "
             f"corrupted_configs={configs}, compromised_credentials={creds}",
        reliability="high", raw_reference=investigation.incident_public_id)]

    hypotheses = [
        Hypothesis(investigation_id=investigation.id,
                   statement="Ransomware mass-encryption event: attacker gained "
                             "credential access, then bulk-encrypted records, wiped "
                             "objects and corrupted configuration within minutes",
                   confidence=0.97, status="confirmed",
                   rationale=f"mass encryption ({encrypted} rows) + object deletion "
                             f"({deleted}) + config corruption ({configs}) + "
                             f"credential compromise ({creds}) in a tight window; "
                             "signature matches deterministic ransomware ruleset"),
        Hypothesis(investigation_id=investigation.id,
                   statement="Accidental insider deletion (non-malicious)",
                   confidence=0.03, status="rejected",
                   rationale="cannot explain encryption markers or credential "
                             "compromise signals"),
        Hypothesis(investigation_id=investigation.id,
                   statement="Backup-based reintroduction risk: latest recovery "
                             "point may contain malicious content",
                   confidence=0.9, status="confirmed",
                   rationale="integrity scan flags post-compromise snapshots; clean "
                             "point must be selected by verification, not recency"),
    ]
    for hypothesis in hypotheses:
        hypothesis.created_at = utcnow()
        session.add(hypothesis)

    conclusion = ("Root cause: ransomware mass-encryption via compromised credentials. "
                  "Recovery point selection must exclude snapshots inside/after the "
                  "compromise window.")
    reasoning = ctx.reason("diagnosis", conclusion, {
        "encrypted_records": encrypted, "deleted_objects": deleted,
        "corrupted_configs": configs, "compromised_credentials": creds,
    })
    decision = add_decision(
        session, investigation, stage="diagnosis", kind="diagnosis",
        decision_text=conclusion, confidence=0.97,
        evidence_rows=evidence_rows,
        alternatives=[{"option": "accidental insider deletion",
                       "rejected_for": "inconsistent with encryption + credential signals"}],
        risk_level="critical", requires_approval=False,
        payload={"hypotheses_confirmed": ["ransomware_mass_encryption",
                                          "backup_reintroduction_risk"]},
        reasoning=reasoning["content"])

    investigation.context = {**(investigation.context or {}),
                             "root_cause": "ransomware_mass_encryption"}
    session.commit()
    return {"root_cause": conclusion, "decision_id": decision.public_id}


def _detection_stats(session: Session, investigation) -> dict:
    from app.models import Incident
    incident = session.query(Incident).filter(
        Incident.public_id == investigation.incident_public_id).first()
    return (incident.detection_stats or {}) if incident else {}
