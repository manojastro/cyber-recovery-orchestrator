"""Integrity checker unit tests: checksum verification + malicious-indicator scan."""
from __future__ import annotations

import pytest

from app.lab.backups import get_snapshot
from app.lab.integrity import (
    evaluate_all_snapshots,
    scan_malicious_indicators,
    verify_checksum,
)


def test_standard_history_latest_snapshot_has_indicators(db, seeded_lab):
    from app.models import BackupSnapshot

    seeded_lab("standard")
    snaps = db.query(BackupSnapshot).order_by(BackupSnapshot.taken_at).all()
    assert len(snaps) == 8
    latest = [s for s in snaps if scan_malicious_indicators(s)[0] > 0]
    assert [s.label for s in latest] == ["BKP-008"]


def test_clean_snapshots_pass_checksum(db, seeded_lab):
    from app.models import BackupSnapshot

    seeded_lab("standard")
    for snap in db.query(BackupSnapshot).all():
        ok, detail = verify_checksum(snap)
        if snap.label == "BKP-008":
            continue  # taken inside compromise window; carries markers but is signed
        assert ok, f"{snap.label} checksum should verify"
        count, findings = scan_malicious_indicators(snap)
        assert count == 0


def test_tampered_manifest_detected(db, seeded_lab):
    from app.models import BackupSnapshot

    seeded_lab("standard")
    snap = get_snapshot(db, "BKP-003")
    original_checksum = snap.checksum
    snap.manifest = {**snap.manifest, "db": {"tables": {}}, "tampered": True}
    ok, detail = verify_checksum(snap)
    assert not ok
    assert detail["match"] is False
    assert detail["stored_checksum"] == original_checksum


def test_corrupted_latest_scenario_fails_verification(db, seeded_lab):
    seeded_lab("corrupted_latest")
    results = evaluate_all_snapshots(db)
    by_label = {r["label"]: r for r in results}
    assert by_label["BKP-008"]["checksum_ok"] is False
    assert "checksum_mismatch" in by_label["BKP-008"]["reasons"]
    assert by_label["BKP-008"]["status"] == "failed"
    # clean point candidates remain intact
    assert by_label["BKP-007"]["status"] == "verified"


def test_evaluate_persists_status(db, seeded_lab):
    seeded_lab("standard")
    results = evaluate_all_snapshots(db)
    db.commit()
    from app.models import BackupSnapshot

    row = db.query(BackupSnapshot).filter(BackupSnapshot.label == "BKP-008").first()
    assert row.integrity_status == "failed"
    assert row.malicious_indicator_count >= 2
    verified_labels = {r["label"] for r in results if r["status"] == "verified"}
    assert "BKP-007" in verified_labels
