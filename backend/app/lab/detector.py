"""Deterministic incident detector (no LLM): anomaly rules over the lab state."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from app.models import ConfigEntry, Credential, DbRecord, Event, Incident, StorageObject
from app.util import new_id, utcnow

logger = logging.getLogger(__name__)

THRESHOLDS = {
    "encrypted_records": 25,
    "deleted_objects": 5,
    "corrupted_configs": 2,
    "compromised_credentials": 1,
}


def scan(session: Session, since: datetime) -> dict:
    encrypted = session.query(DbRecord).filter(
        DbRecord.encrypted.is_(True), DbRecord.mutated_at >= since).count()
    deleted = session.query(StorageObject).filter(
        StorageObject.deleted.is_(True), StorageObject.mutated_at >= since).count()
    corrupted = session.query(ConfigEntry).filter(
        ConfigEntry.integrity_ok.is_(False), ConfigEntry.mutated_at >= since).count()
    compromised = session.query(Credential).filter(
        Credential.status == "compromised", Credential.compromised_at >= since).count()
    return {
        "window_start": since.isoformat(),
        "encrypted_records": encrypted,
        "deleted_objects": deleted,
        "corrupted_configs": corrupted,
        "compromised_credentials": compromised,
        "thresholds": THRESHOLDS,
    }


def evaluate(stats: dict) -> Tuple[bool, list]:
    fired = []
    if stats["encrypted_records"] >= THRESHOLDS["encrypted_records"]:
        fired.append("mass_record_encryption")
    if stats["deleted_objects"] >= THRESHOLDS["deleted_objects"]:
        fired.append("mass_object_deletion")
    if stats["corrupted_configs"] >= THRESHOLDS["corrupted_configs"]:
        fired.append("config_corruption")
    if stats["compromised_credentials"] >= THRESHOLDS["compromised_credentials"]:
        fired.append("credential_compromise")
    # An INCIDENT requires the ransomware signature: mass encryption plus at
    # least one corroborating destruction signal.
    return ("mass_record_encryption" in fired and len(fired) >= 2), fired


def detect_incident(session: Session, incident: Incident) -> Incident:
    """Run the deterministic detection pass over the injected incident."""
    now = utcnow()
    stats = scan(session, since=incident.started_at - timedelta(minutes=1))
    detected, fired_rules = evaluate(stats)
    stats["fired_rules"] = fired_rules
    stats["detected"] = detected
    incident.detection_stats = stats
    incident.detected_at = now
    if detected:
        incident.status = "open"
        incident.summary = (
            "DETECTED: ransomware signature confirmed "
            f"(rules fired: {', '.join(fired_rules)}); recovery workflow required"
        )
        session.add(Event(
            public_id=new_id("evt-"), ts=now, event_type="incident_detected",
            source="deterministic-rule-engine", severity="critical",
            message=f"Incident {incident.public_id} raised; rules: {', '.join(fired_rules)}",
            payload={"incident_public_id": incident.public_id, "stats": stats},
            incident_public_id=incident.public_id,
        ))
    else:
        incident.status = "not_detected"
        incident.summary = "Signals below incident thresholds; no incident raised."
    session.commit()
    logger.info("detection pass: detected=%s rules=%s", detected, fired_rules)
    return incident
