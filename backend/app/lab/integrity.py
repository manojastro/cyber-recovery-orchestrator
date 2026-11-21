"""Snapshot integrity verification and malicious-indicator scanning."""
from __future__ import annotations

from typing import Dict, List, Tuple

from sqlalchemy.orm import Session

from app.models import BackupSnapshot
from app.util import sha256_of


def verify_checksum(snapshot: BackupSnapshot) -> Tuple[bool, dict]:
    """Recompute the manifest digest and compare with the signed checksum."""
    recomputed = sha256_of(snapshot.manifest)
    ok = recomputed == snapshot.checksum
    detail = {
        "algorithm": snapshot.checksum_algorithm,
        "stored_checksum": snapshot.checksum,
        "recomputed_checksum": recomputed,
        "match": ok,
    }
    return ok, detail


def scan_malicious_indicators(snapshot: BackupSnapshot) -> Tuple[int, List[dict]]:
    """Scan manifest samples for hidden malicious markers (encrypted records /
    encrypted object versions written inside the compromise window)."""
    findings: List[dict] = []
    for sample in (snapshot.manifest or {}).get("samples", []):
        marker = sample.get("marker")
        if marker:
            findings.append({
                "kind": sample.get("kind"),
                "table": sample.get("table"),
                "bucket": sample.get("bucket"),
                "key": sample.get("key"),
                "marker": marker,
            })
    return len(findings), findings


def evaluate_snapshot(session: Session, snapshot: BackupSnapshot) -> dict:
    """Full evaluation: checksum + indicator scan. Persists status on the row."""
    checksum_ok, checksum_detail = verify_checksum(snapshot)
    indicator_count, findings = scan_malicious_indicators(snapshot)
    if not checksum_ok:
        status = "failed"
        reasons = ["checksum_mismatch"]
    elif indicator_count > 0:
        status = "failed"
        reasons = ["malicious_indicators"]
    else:
        status = "verified"
        reasons = []
    snapshot.integrity_status = status
    snapshot.malicious_indicator_count = indicator_count
    snapshot.integrity_detail = {
        "checksum": checksum_detail,
        "indicators": findings,
        "reasons": reasons,
    }
    session.flush()
    return {
        "label": snapshot.label,
        "public_id": snapshot.public_id,
        "taken_at": snapshot.taken_at.isoformat(),
        "status": status,
        "checksum_ok": checksum_ok,
        "indicator_count": indicator_count,
        "findings": findings,
        "reasons": reasons,
        "completeness": snapshot.completeness,
    }


def evaluate_all_snapshots(session: Session) -> List[dict]:
    return [evaluate_snapshot(session, snap)
            for snap in session.query(BackupSnapshot).order_by(BackupSnapshot.taken_at)]


def live_database_marker_count(session: Session) -> int:
    from app.models import DbRecord
    return session.query(DbRecord).filter(
        DbRecord.encrypted.is_(True), DbRecord.deleted.is_(False)).count()


def summary(results: List[dict]) -> Dict[str, object]:
    verified = [r["label"] for r in results if r["status"] == "verified"]
    failed = [r["label"] for r in results if r["status"] == "failed"]
    return {"verified": verified, "failed": failed, "total": len(results)}
