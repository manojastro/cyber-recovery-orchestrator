"""Ransomware incident injection: mass encryption, object deletion, config
corruption, credential compromise - plus the timeline events that make the
damage discoverable by the deterministic detector."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.lab import topology
from app.models import (
    Asset,
    ConfigEntry,
    Credential,
    DbRecord,
    Event,
    Incident,
    StorageObject,
)
from app.util import deterministic_id, new_id, utcnow

logger = logging.getLogger(__name__)

ENCRYPT_FRACTION = 0.7
DELETE_OBJECT_FRACTION = 0.3
ENCRYPT_OBJECT_FRACTION = 0.4
INSERTED_ENCRYPTED_ROWS_PER_TABLE = 12


def inject_ransomware(session: Session, scenario: str,
                      now: Optional[datetime] = None) -> Incident:
    """Inject the incident at T0 and emit timeline events. Returns the Incident
    row in status 'injecting' (detection happens in lab.detector)."""
    now = now or utcnow()
    t0 = topology.compromise_start(now)

    # --- database: mass encryption markers ---
    encrypted_count = 0
    inserted_count = 0
    tables = sorted(topology.DB_TABLE_SIZES)
    for table in tables:
        records = session.query(DbRecord).filter(
            DbRecord.table_name == table, DbRecord.deleted.is_(False)
        ).order_by(DbRecord.id).all()
        target = int(len(records) * ENCRYPT_FRACTION)
        for record in records[:target]:
            if not record.encrypted:
                record.encrypted = True
                record.mutated_at = t0
                encrypted_count += 1
        for i in range(INSERTED_ENCRYPTED_ROWS_PER_TABLE):
            inserted_count += 1
            session.add(DbRecord(
                table_name=table, record_key=f"{table}-ransom-{i:03d}",
                payload=f"{{\"ransom_note\":\"locked\"}}", encrypted=True,
                created_at=t0, mutated_at=t0,
            ))

    # --- storage: deleted objects + encrypted versions ---
    deleted_objects = 0
    encrypted_objects = 0
    objects = session.query(StorageObject).filter(
        StorageObject.deleted.is_(False)).order_by(StorageObject.id).all()
    delete_target = int(len(objects) * DELETE_OBJECT_FRACTION)
    encrypt_target = int(len(objects) * ENCRYPT_OBJECT_FRACTION)
    for obj in objects[:delete_target]:
        obj.deleted = True
        obj.mutated_at = t0 + timedelta(seconds=30)
        deleted_objects += 1
    for obj in objects[delete_target:delete_target + encrypt_target]:
        obj.version += 1
        obj.encrypted = True
        obj.mutated_at = t0 + timedelta(seconds=30)
        encrypted_objects += 1

    # --- configuration corruption ---
    corrupt_keys = ["payments.provider.endpoint", "identity.token.ttl",
                    "feature.checkout.v2", "db.pool.max-size"]
    corrupted_configs = 0
    for key in corrupt_keys:
        entry = session.query(ConfigEntry).filter(ConfigEntry.key == key).first()
        if entry:
            entry.value = "<CORRUPTED>"
            entry.integrity_ok = False
            entry.mutated_at = t0 + timedelta(seconds=60)
            corrupted_configs += 1

    # --- credential compromise ---
    compromised_principals: List[str] = []
    for principal in topology.COMPROMISED_PRINCIPALS:
        cred = session.query(Credential).filter(Credential.principal == principal).first()
        if cred:
            cred.status = "compromised"
            cred.compromised_at = t0 + timedelta(seconds=90)
            compromised_principals.append(principal)

    # --- service degradation ---
    service_damage = {
        "web-frontend": ("down", 10), "reporting-service": ("down", 0),
        "order-service": ("degraded", 40), "payment-service": ("degraded", 35),
        "customer-service": ("degraded", 45), "identity-service": ("degraded", 50),
    }
    for name, (state, health) in service_damage.items():
        asset = session.query(Asset).filter(Asset.name == name).first()
        if asset:
            asset.state = state
            asset.health = health
    for name in ("core-postgres", "object-storage", "config-store"):
        asset = session.query(Asset).filter(Asset.name == name).first()
        if asset:
            asset.data_integrity_flag = False
            asset.health = min(asset.health, 60)
            asset.state = "degraded"

    # --- timeline events with affected-asset references ---
    event_specs = [
        ("mass_encryption_started", t0,
         f"{encrypted_count} db records marked encrypted across {len(tables)} tables",
         {"assets": ["core-postgres"], "encrypted_records": encrypted_count,
          "tables": tables}),
        ("storage_objects_deleted", t0 + timedelta(seconds=30),
         f"{deleted_objects} storage objects deleted; {encrypted_objects} re-written encrypted",
         {"assets": ["object-storage"], "deleted": deleted_objects,
          "encrypted_versions": encrypted_objects}),
        ("config_entries_corrupted", t0 + timedelta(seconds=60),
         f"{corrupted_configs} configuration entries corrupted",
         {"assets": ["config-store"], "keys": corrupt_keys}),
        ("credential_compromise", t0 + timedelta(seconds=90),
         f"credentials compromised: {', '.join(compromised_principals)}",
         {"assets": ["identity-service"], "principals": compromised_principals}),
        ("service_degradation", t0 + timedelta(seconds=120),
         "tier1/tier2 services degraded or down after data plane corruption",
         {"assets": list(service_damage.keys())}),
    ]
    events: List[Event] = []
    for event_type, ts, message, payload in event_specs:
        event = Event(
            public_id=new_id("evt-"), ts=ts, event_type=event_type,
            source="simulator:incident-injection", severity="critical",
            message=message, payload=payload,
        )
        session.add(event)
        events.append(event)

    incident = Incident(
        # Deterministic id for the first incident of a freshly seeded lab so
        # identical runs produce identical public ids (determinism guarantee).
        public_id=deterministic_id("incident", scenario),
        scenario=scenario,
        title="Suspected ransomware: mass record encryption across core data plane",
        severity="critical", status="injecting",
        started_at=t0, detected_at=now,
        summary="Injection complete; awaiting deterministic detection pass.",
        detection_stats={},
    )
    session.add(incident)
    for event in events:
        event.incident_public_id = incident.public_id
    session.commit()

    # Ensure unique public id on same-hour re-trigger.
    clash = session.query(Incident).filter(
        Incident.public_id == incident.public_id,
        Incident.id != incident.id,
    ).count()
    if clash:
        incident.public_id = f"{incident.public_id}-{new_id('')[:8]}"
        session.commit()

    logger.info("incident injected: %s records=%s objects_deleted=%s configs=%s creds=%s",
                incident.public_id, encrypted_count, deleted_objects,
                corrupted_configs, len(compromised_principals))
    return incident
