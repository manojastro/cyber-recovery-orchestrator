"""Backup snapshot generation: manifests, checksums, hidden malicious markers."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy.orm import Session

from app.lab import topology
from app.models import BackupSnapshot, ConfigEntry, DbRecord, StorageObject
from app.util import canonical_json, deterministic_id, sha256_of, utcnow

logger = logging.getLogger(__name__)


def build_manifest(session: Session, label: str, taken_at: datetime,
                   with_markers: bool = False) -> dict:
    """Build a consolidated manifest of lab state at `taken_at` (approximation:
    counts over rows that existed at that time). Samples carry optional hidden
    malicious markers for snapshots taken inside/after the compromise window."""
    db_tables = {}
    for table in topology.DB_TABLE_SIZES:
        count = session.query(DbRecord).filter(
            DbRecord.table_name == table, DbRecord.created_at <= taken_at
        ).count()
        db_tables[table] = {"count": count}
    buckets = {}
    for bucket in topology.STORAGE_BUCKETS:
        count = session.query(StorageObject).filter(
            StorageObject.bucket == bucket, StorageObject.created_at <= taken_at
        ).count()
        buckets[bucket] = {"objects": count}
    config_entries = session.query(ConfigEntry).count()

    samples: List[dict] = [
        {"kind": "db_record", "table": t, "key": f"{t}-0001", "marker": None}
        for t in ("products", "customers", "orders")
    ] + [{"kind": "storage_object", "bucket": b, "key": f"{b}/object-000.bin",
          "marker": None} for b in topology.STORAGE_BUCKETS]

    if with_markers:
        # Hidden attributes: records encrypted after the compromise window leaked
        # into this snapshot. The scanner must catch these.
        samples += [
            {"kind": "db_record", "table": "orders", "key": "orders-ransom-001",
             "marker": "encrypted_record_marker"},
            {"kind": "storage_object", "bucket": "app-data",
             "key": "app-data/ransom.locked", "marker": "encrypted_object_version"},
        ]

    return {
        "label": label,
        "taken_at": taken_at.isoformat(),
        "snapshot_type": "consolidated",
        "db": {"tables": db_tables},
        "storage": {"buckets": buckets},
        "config": {"entries": config_entries},
        "samples": samples,
    }


def generate_backup_history(session: Session, scenario: str = "standard",
                            now: Optional[datetime] = None) -> List[str]:
    """Create the periodic backup history. Snapshots taken after the compromise
    window start carry malicious markers; `corrupted_latest` additionally has a
    checksum that will not match its tampered manifest."""
    now = now or utcnow()
    compromise_start = topology.compromise_start(now)
    labels: List[str] = []

    for index in range(1, topology.SNAPSHOT_COUNT + 1):
        taken_at = topology.snapshot_taken_at(now, index)
        label = f"BKP-{index:03d}"
        after_compromise = taken_at >= compromise_start
        manifest = build_manifest(session, label, taken_at, with_markers=after_compromise)
        checksum = sha256_of(manifest)

        if scenario == "corrupted_latest" and index == topology.SNAPSHOT_COUNT:
            # Corrupt the LATEST backup post-signing: naive "latest restore"
            # would reintroduce corruption.
            manifest["db"]["tables"]["orders"]["count"] += 999
            manifest["tampered"] = True

        total_rows = sum(v["count"] for v in manifest["db"]["tables"].values())
        session.add(BackupSnapshot(
            public_id=deterministic_id("snapshot", label),
            label=label, snapshot_type="consolidated", taken_at=taken_at,
            checksum_algorithm="sha256", checksum=checksum, manifest=manifest,
            integrity_status="unverified",
            completeness=1.0,
            size_bytes=max(total_rows * 4096, 4096),
            created_by="lab-generator",
        ))
        labels.append(label)

    session.flush()
    return labels


def get_snapshot(session: Session, label_or_public_id: str) -> Optional[BackupSnapshot]:
    query = session.query(BackupSnapshot)
    snap = query.filter(BackupSnapshot.label == label_or_public_id).first()
    if snap is None:
        snap = query.filter(BackupSnapshot.public_id == label_or_public_id).first()
    return snap
