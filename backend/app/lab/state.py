"""Lab state: seeding, reset, pre-recovery image capture, rollback restore."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.lab import backups, topology
from app.models import (
    Action,
    Approval,
    Asset,
    BackupSnapshot,
    ConfigEntry,
    Credential,
    DbRecord,
    Decision,
    Dependency,
    Event,
    Evidence,
    Hypothesis,
    Incident,
    Investigation,
    MetricSnapshot,
    Outcome,
    RiskAssessment,
    StageRun,
    StorageObject,
    ToolCall,
    Validation,
)
from app.util import deterministic_id, new_id, utcnow

logger = logging.getLogger(__name__)

WORKFLOW_TABLES = (ToolCall, MetricSnapshot, Validation, Outcome, Action, Approval,
                   RiskAssessment, Decision, Hypothesis, Evidence, StageRun,
                   Investigation, Incident, Event)
# EvaluationRun is deliberately NOT wiped: reseeding preserves evaluation history.
LAB_TABLES = (DbRecord, StorageObject, ConfigEntry, Credential, BackupSnapshot,
              Dependency, Asset)


def wipe_all(session: Session) -> None:
    """Full clean slate: lab state + workflow case files + audit."""
    for model in WORKFLOW_TABLES + LAB_TABLES:
        session.execute(delete(model))
    session.flush()


def seed_lab(session: Session, scenario: str = "standard", now: Optional[datetime] = None) -> dict:
    """Seed the enterprise lab: assets, dependencies, data plane, backup history.

    Deterministic content; timestamps are relative to `now` so ordering is stable.
    """
    now = now or utcnow()

    # --- assets ---
    for name, (asset_type, tier, criticality, owner) in topology.ASSETS.items():
        session.add(Asset(
            public_id=deterministic_id("asset", name),
            name=name, asset_type=asset_type, tier=tier, criticality=criticality,
            owner=owner, state="running", health=100, version="1.4.2",
            data_integrity_flag=True,
            extra={"region": "lab-local", "runtime": "in-process-simulation"},
        ))

    # --- typed dependency edges ---
    for src, dst, dep_type in topology.DEPENDENCIES:
        session.add(Dependency(from_asset=src, to_asset=dst, dep_type=dep_type))

    # --- database rows (pristine payloads) ---
    seq = 0
    for table, count in topology.DB_TABLE_SIZES.items():
        for i in range(count):
            seq += 1
            created = now - __import__("datetime").timedelta(days=30, minutes=seq)
            session.add(DbRecord(
                table_name=table, record_key=f"{table}-{i:04d}",
                payload=f"{table}#{{\"i\":{i},\"status\":\"ok\"}}",
                encrypted=False, corrupted=False, deleted=False,
                created_at=created,
            ))

    # --- storage objects with versions ---
    for bucket, count in topology.STORAGE_BUCKETS.items():
        for i in range(count):
            created = now - __import__("datetime").timedelta(days=15, minutes=i)
            session.add(StorageObject(
                bucket=bucket, obj_key=f"{bucket}/object-{i:03d}.bin", version=1,
                size_bytes=1024 * (i + 1), content_digest=new_id("sha-"),
                encrypted=False, deleted=False, created_at=created,
            ))

    # --- configuration entries ---
    for key in topology.CONFIG_KEYS:
        baseline = f"baseline-value::{key}"
        session.add(ConfigEntry(key=key, baseline_value=baseline, value=baseline,
                                integrity_ok=True))

    # --- credentials ---
    for principal, kind in topology.CREDENTIAL_PRINCIPALS:
        session.add(Credential(principal=principal, kind=kind, status="active",
                               generation=1, secret_hint="***"))

    session.flush()

    # --- backup history ---
    snapshot_labels = backups.generate_backup_history(session, scenario=scenario, now=now)

    session.commit()
    return {
        "assets": len(topology.ASSETS),
        "dependencies": len(topology.DEPENDENCIES),
        "db_records": sum(topology.DB_TABLE_SIZES.values()),
        "storage_objects": sum(topology.STORAGE_BUCKETS.values()),
        "config_entries": len(topology.CONFIG_KEYS),
        "credentials": len(topology.CREDENTIAL_PRINCIPALS),
        "snapshots": snapshot_labels,
        "scenario": scenario,
    }


# ---------- pre-state image / rollback ----------

def capture_pre_state(session: Session) -> dict:
    """Serialize mutable lab tables so a failed recovery can be rolled back."""

    def asset_rows():
        return [{"name": a.name, "state": a.state, "health": a.health,
                 "data_integrity_flag": a.data_integrity_flag} for a in session.query(Asset)]

    records = [{
        "table_name": r.table_name, "record_key": r.record_key, "payload": r.payload,
        "encrypted": r.encrypted, "corrupted": r.corrupted, "deleted": r.deleted,
        "created_at": r.created_at.isoformat(), "mutated_at": _iso(r.mutated_at),
    } for r in session.query(DbRecord)]
    objects = [{
        "bucket": o.bucket, "obj_key": o.obj_key, "version": o.version,
        "size_bytes": o.size_bytes, "content_digest": o.content_digest,
        "encrypted": o.encrypted, "deleted": o.deleted,
        "created_at": o.created_at.isoformat(), "mutated_at": _iso(o.mutated_at),
    } for o in session.query(StorageObject)]
    configs = [{
        "key": c.key, "baseline_value": c.baseline_value, "value": c.value,
        "integrity_ok": c.integrity_ok, "mutated_at": _iso(c.mutated_at),
    } for c in session.query(ConfigEntry)]
    creds = [{
        "principal": cr.principal, "kind": cr.kind, "status": cr.status,
        "generation": cr.generation, "secret_hint": "***",
        "compromised_at": _iso(cr.compromised_at), "rotated_at": _iso(cr.rotated_at),
    } for cr in session.query(Credential)]
    return {"assets": asset_rows(), "db_records": records, "storage_objects": objects,
            "config_entries": configs, "credentials": creds}


def restore_pre_state(session: Session, image: dict) -> int:
    """Replace current lab state with the captured image. Returns row count restored."""
    session.execute(delete(DbRecord))
    session.execute(delete(StorageObject))
    session.execute(delete(ConfigEntry))
    session.execute(delete(Credential))
    for row in image.get("db_records", []):
        session.add(DbRecord(
            table_name=row["table_name"], record_key=row["record_key"],
            payload=row["payload"], encrypted=row["encrypted"], corrupted=row["corrupted"],
            deleted=row["deleted"], created_at=_dt(row["created_at"]),
            mutated_at=_dt(row["mutated_at"]),
        ))
    for row in image.get("storage_objects", []):
        session.add(StorageObject(
            bucket=row["bucket"], obj_key=row["obj_key"], version=row["version"],
            size_bytes=row["size_bytes"], content_digest=row["content_digest"],
            encrypted=row["encrypted"], deleted=row["deleted"],
            created_at=_dt(row["created_at"]), mutated_at=_dt(row["mutated_at"]),
        ))
    for row in image.get("config_entries", []):
        session.add(ConfigEntry(key=row["key"], baseline_value=row["baseline_value"],
                                value=row["value"], integrity_ok=row["integrity_ok"],
                                mutated_at=_dt(row["mutated_at"])))
    for row in image.get("credentials", []):
        session.add(Credential(principal=row["principal"], kind=row["kind"],
                               status=row["status"], generation=row["generation"],
                               secret_hint=row.get("secret_hint", "***"),
                               compromised_at=_dt(row["compromised_at"]),
                               rotated_at=_dt(row["rotated_at"])))
    for row in image.get("assets", []):
        asset = session.query(Asset).filter(Asset.name == row["name"]).first()
        if asset:
            asset.state = row["state"]
            asset.health = row["health"]
            asset.data_integrity_flag = row["data_integrity_flag"]
    restored = (len(image.get("db_records", [])) + len(image.get("storage_objects", [])))
    session.commit()
    return restored


def _iso(dt):
    return dt.isoformat() if dt else None


def _dt(value):
    from datetime import datetime as _dt_type

    if value is None:
        return None
    if isinstance(value, _dt_type):
        return value
    return datetime.fromisoformat(value)
