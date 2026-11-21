"""Registered recovery tools. Handlers operate on lab state persisted in the
project database (honest in-process simulation; no container-level restore)."""
from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from app.graph.dependency_graph import build_graph_from_db, recovery_order
from app.lab.business_txn import run_business_transaction
from app.lab.integrity import evaluate_all_snapshots, evaluate_snapshot
from app.lab.backups import get_snapshot
from app.models import (
    Asset,
    ConfigEntry,
    Credential,
    DbRecord,
    Event,
    StorageObject,
)
from app.tools.base import HIGH, LOW, MEDIUM, ToolRegistry, ToolSpec, validate_payload
from app.util import new_id, sha256_of, utcnow


def _obj(schema: Dict[str, Any], required: list = None) -> Dict[str, Any]:
    return {"type": "object", "properties": schema, "required": required or []}


def _snapshot_label_schema() -> Dict[str, Any]:
    return {"snapshot_label": {"type": "string"}}


def _asset_name_schema() -> Dict[str, Any]:
    return {"asset_name": {"type": "string"}}


# ---------- restore handlers (HIGH risk) ----------

def _restore_database_snapshot(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    snap = get_snapshot(session, payload["snapshot_label"])
    if snap is None:
        raise ValueError(f"unknown snapshot: {payload['snapshot_label']}")
    cutoff = snap.taken_at
    reverted = 0
    removed = 0
    for record in session.query(DbRecord).all():
        created_after = record.created_at > cutoff
        if created_after:
            session.delete(record)
            removed += 1
            continue
        mutated = (record.encrypted or record.corrupted or record.deleted)
        if mutated:
            record.encrypted = False
            record.corrupted = False
            record.deleted = False
            record.mutated_at = None
            reverted += 1
    db_asset = session.query(Asset).filter(Asset.name == "core-postgres").first()
    if db_asset:
        db_asset.data_integrity_flag = True
        db_asset.state = "running"
        db_asset.health = 100
    session.flush()
    session.add(Event(public_id=new_id("evt-"), ts=utcnow(),
                      event_type="restore_database_snapshot", source="tool",
                      severity="info",
                      message=f"core-postgres restored from {snap.label}",
                      payload={"snapshot": snap.label, "reverted": reverted,
                               "removed_post_snapshot_rows": removed}))
    return {"summary": f"database restored from {snap.label}: {reverted} rows reverted, "
                       f"{removed} post-snapshot rows removed",
            "snapshot": snap.label, "rows_reverted": reverted, "rows_removed": removed}


def _restore_storage_objects(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    snap = get_snapshot(session, payload["snapshot_label"])
    if snap is None:
        raise ValueError(f"unknown snapshot: {payload['snapshot_label']}")
    cutoff = snap.taken_at
    manifest_counts = (snap.manifest.get("storage", {}).get("buckets", {}))
    restored_versions = 0
    removed = 0
    for obj in session.query(StorageObject).all():
        if obj.created_at > cutoff:
            session.delete(obj)
            removed += 1
            continue
        if obj.encrypted or obj.deleted:
            obj.encrypted = False
            obj.deleted = False
            obj.mutated_at = None
            restored_versions += 1
    asset = session.query(Asset).filter(Asset.name == "object-storage").first()
    if asset:
        asset.data_integrity_flag = True
        asset.state = "running"
        asset.health = 100
    # reconcile object counts against manifest expectations
    reconciled = {}
    for bucket, spec in manifest_counts.items():
        live = session.query(StorageObject).filter(
            StorageObject.bucket == bucket, StorageObject.deleted.is_(False)).count()
        expected = int(spec.get("objects", live))
        missing = expected - live
        for i in range(max(missing, 0)):
            session.add(StorageObject(
                bucket=bucket, obj_key=f"{bucket}/restored-{i:03d}.bin", version=1,
                size_bytes=4096, content_digest=sha256_of({"b": bucket, "i": i}),
                encrypted=False, deleted=False, created_at=cutoff))
        reconciled[bucket] = {"expected": expected, "live_after_restore": live + max(missing, 0)}
    session.flush()
    session.add(Event(public_id=new_id("evt-"), ts=utcnow(),
                      event_type="restore_storage_objects", source="tool",
                      severity="info",
                      message=f"object storage restored from {snap.label}",
                      payload={"snapshot": snap.label, "restored_versions": restored_versions}))
    return {"summary": f"object storage restored from {snap.label}: "
                       f"{restored_versions} objects recovered, {removed} removed",
            "snapshot": snap.label, "objects_recovered": restored_versions,
            "buckets": reconciled}


def _restore_configuration(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    snap = get_snapshot(session, payload["snapshot_label"])
    if snap is None:
        raise ValueError(f"unknown snapshot: {payload['snapshot_label']}")
    restored = 0
    for entry in session.query(ConfigEntry).all():
        if not entry.integrity_ok or entry.value != entry.baseline_value:
            entry.value = entry.baseline_value
            entry.integrity_ok = True
            entry.mutated_at = None
            restored += 1
    asset = session.query(Asset).filter(Asset.name == "config-store").first()
    if asset:
        asset.data_integrity_flag = True
        asset.state = "running"
        asset.health = 100
    session.flush()
    return {"summary": f"configuration restored from {snap.label}: "
                       f"{restored} entries reset to baseline",
            "snapshot": snap.label, "entries_restored": restored}


# ---------- identity / services ----------

def _rotate_compromised_credentials(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    rotated = []
    for cred in session.query(Credential).filter(Credential.status == "compromised").all():
        cred.status = "active"
        cred.generation += 1
        cred.compromised_at = None
        cred.rotated_at = utcnow()
        rotated.append(cred.principal)
    identity = session.query(Asset).filter(Asset.name == "identity-service").first()
    if identity and identity.state != "running":
        identity.state = "degraded"
        identity.health = max(identity.health, 60)
    session.flush()
    session.add(Event(public_id=new_id("evt-"), ts=utcnow(),
                      event_type="rotate_compromised_credentials", source="tool",
                      severity="warning",
                      message=f"rotated credentials: {', '.join(rotated) or 'none'}",
                      payload={"principals": rotated}))
    return {"summary": f"rotated {len(rotated)} compromised credential(s)",
            "principals": rotated}


def _restart_service(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    name = payload["asset_name"]
    asset = session.query(Asset).filter(Asset.name == name).first()
    if asset is None:
        raise ValueError(f"unknown asset: {name}")
    previous = asset.state
    asset.state = "running"
    asset.health = 100
    if asset.asset_type in ("database", "storage", "config"):
        asset.data_integrity_flag = True
    session.flush()
    return {"summary": f"{name} restarted ({previous} -> running, health 100)",
            "asset": name, "previous_state": previous, "state": "running",
            "health": 100}


# ---------- read-only / low-risk probes ----------

def _run_integrity_check(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    target = payload.get("target")
    result: Dict[str, Any] = {}
    if target in (None, "backup_catalog"):
        evaluations = evaluate_all_snapshots(session)
        failed = [e["label"] for e in evaluations if e["status"] == "failed"]
        result = {"kind": "backup_catalog", "evaluations": evaluations,
                  "failed_snapshots": failed}
    elif target == "database":
        bad = session.query(DbRecord).filter(
            DbRecord.encrypted.is_(True), DbRecord.deleted.is_(False)).count()
        corrupted = session.query(DbRecord).filter(
            DbRecord.corrupted.is_(True), DbRecord.deleted.is_(False)).count()
        deleted_active = session.query(DbRecord).filter(DbRecord.deleted.is_(True)).count()
        result = {"kind": "database", "encrypted_markers": bad,
                  "corrupted_rows": corrupted, "soft_deleted_rows": deleted_active,
                  "clean": bad == 0 and corrupted == 0}
    elif target == "storage":
        encrypted = session.query(StorageObject).filter(
            StorageObject.encrypted.is_(True), StorageObject.deleted.is_(False)).count()
        deleted = session.query(StorageObject).filter(
            StorageObject.deleted.is_(True)).count()
        result = {"kind": "storage", "encrypted_versions": encrypted,
                  "deleted_objects": deleted,
                  "clean": encrypted == 0 and deleted == 0}
    elif target == "configuration":
        bad = session.query(ConfigEntry).filter(
            ConfigEntry.integrity_ok.is_(False)).count()
        result = {"kind": "configuration", "corrupted_entries": bad, "clean": bad == 0}
    else:
        raise ValueError(f"unknown integrity check target: {target}")
    clean = result.get("clean", True)
    if clean:
        result["summary"] = "integrity OK"
    else:
        counts = {k: v for k, v in result.items()
                  if k.endswith(("markers", "rows", "entries", "versions"))}
        result["summary"] = f"integrity violations found in {result['kind']}: {counts}"
    return result


def _query_dependency_graph(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    graph = build_graph_from_db(session)
    scope = set(payload.get("scope") or graph.nodes())
    edges = [{"from_asset": u, "to_asset": v,
              "dep_type": graph.graph.edges[u, v]["dep_type"]}
             for u, v in graph.graph.edges]
    order = recovery_order(graph, scope)
    nodes = [{"name": n, **{k: v for k, v in graph.assets[n].items()}} for n in sorted(scope)]
    return {"summary": f"dependency graph queried; recovery order computed for "
                       f"{len(scope)} assets",
            "nodes": nodes, "edges": edges, "recovery_order": order,
            "acyclic": graph.is_acyclic()}


def _query_backup_catalog(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    from app.models import BackupSnapshot
    rows = session.query(BackupSnapshot).order_by(BackupSnapshot.taken_at.desc()).all()
    entries = []
    for row in rows:
        evaluation = evaluate_snapshot(session, row)
        entries.append(evaluation)
    return {"summary": f"backup catalog queried: {len(entries)} snapshots evaluated",
            "snapshots": entries}


def _run_service_health_check(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    name = payload.get("asset_name")
    query = session.query(Asset)
    assets = ([query.filter(Asset.name == name).first()] if name
              else query.filter(Asset.asset_type.in_(("service", "identity"))).all())
    results = []
    healthy = True
    for asset in assets:
        if asset is None:
            raise ValueError(f"unknown asset: {name}")
        passed = asset.state == "running" and asset.health >= 90
        healthy = healthy and passed
        results.append({"asset": asset.name, "state": asset.state,
                        "health": asset.health, "healthy": passed})
    return {"summary": f"health check: {'all healthy' if healthy else 'unhealthy assets found'}",
            "checks": results, "healthy": healthy}


_AUTH_STEP_ASSETS = ["web-frontend", "order-service", "customer-service",
                     "payment-service"]


def _run_business_transaction_test(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    outcome = run_business_transaction(session)
    return {"summary": ("business transaction PASSED (login->browse->cart->checkout"
                        "->order created)" if outcome["passed"] else
                        f"business transaction FAILED at step '{outcome['failed_step']}'"),
            **outcome}


def _query_incident_timeline(session: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    from app.models import Incident
    incident_public_id = payload.get("incident_public_id")
    query = session.query(Event)
    if incident_public_id:
        query = query.filter(Event.incident_public_id == incident_public_id)
    events = query.order_by(Event.ts).all()
    return {"summary": f"incident timeline queried: {len(events)} events",
            "events": [{"public_id": e.public_id, "ts": e.ts.isoformat(),
                        "event_type": e.event_type, "source": e.source,
                        "severity": e.severity, "message": e.message,
                        "payload": e.payload} for e in events]}


def register_recovery_tools(registry: ToolRegistry) -> None:
    registry.register(ToolSpec(
        name="query_incident_timeline",
        purpose="Read the ordered event timeline of an incident (scope evidence).",
        input_schema=_obj({"incident_public_id": {"type": "string"}}),
        output_schema=_obj({"events": {"type": "array"}}),
        handler=_query_incident_timeline, risk_level=LOW, timeout_s=30.0))

    registry.register(ToolSpec(
        name="restore_database_snapshot",
        purpose="Restore core-postgres to a verified snapshot (revert encryption/"
                "corruption, drop post-snapshot rows).",
        input_schema=_obj(_snapshot_label_schema(), required=["snapshot_label"]),
        output_schema=_obj({"snapshot": {"type": "string"},
                            "rows_reverted": {"type": "integer"}}),
        handler=_restore_database_snapshot, risk_level=HIGH, timeout_s=120.0))

    registry.register(ToolSpec(
        name="restore_storage_objects",
        purpose="Restore MinIO-style object storage from a snapshot manifest: undo "
                "encrypted versions/deletions, reconcile counts.",
        input_schema=_obj(_snapshot_label_schema(), required=["snapshot_label"]),
        output_schema=_obj({"objects_recovered": {"type": "integer"}}),
        handler=_restore_storage_objects, risk_level=HIGH, timeout_s=120.0))

    registry.register(ToolSpec(
        name="restore_configuration",
        purpose="Reset corrupted configuration entries to their signed baseline values.",
        input_schema=_obj(_snapshot_label_schema(), required=["snapshot_label"]),
        output_schema=_obj({"entries_restored": {"type": "integer"}}),
        handler=_restore_configuration, risk_level=HIGH, timeout_s=60.0))

    registry.register(ToolSpec(
        name="rotate_compromised_credentials",
        purpose="Rotate every credential marked compromised so stolen secrets stop working.",
        input_schema=_obj({}),
        output_schema=_obj({"principals": {"type": "array"}}),
        handler=_rotate_compromised_credentials, risk_level=MEDIUM, timeout_s=60.0))

    registry.register(ToolSpec(
        name="restart_service",
        purpose="Restart a service/infra component after data restoration.",
        input_schema=_obj(_asset_name_schema(), required=["asset_name"]),
        output_schema=_obj({"asset": {"type": "string"}, "state": {"type": "string"}}),
        handler=_restart_service, risk_level=MEDIUM, timeout_s=60.0))

    registry.register(ToolSpec(
        name="run_integrity_check",
        purpose="Verify integrity: backup catalog checksums/markers, database markers, "
                "storage versions, configuration corruption.",
        input_schema=_obj({"target": {"type": "string",
                                      "enum": ["backup_catalog", "database", "storage",
                                               "configuration"]},
                           "snapshot_label": {"type": "string"}}),
        output_schema=_obj({"clean": {"type": "boolean"}}),
        handler=_run_integrity_check, risk_level=LOW, timeout_s=60.0))

    registry.register(ToolSpec(
        name="query_dependency_graph",
        purpose="Read the application dependency graph and compute a legal recovery "
                "order (topological, tier-aware).",
        input_schema=_obj({"scope": {"type": "array"}}),
        output_schema=_obj({"nodes": {"type": "array"}, "edges": {"type": "array"},
                            "recovery_order": {"type": "array"}}),
        handler=_query_dependency_graph, risk_level=LOW, timeout_s=30.0))

    registry.register(ToolSpec(
        name="query_backup_catalog",
        purpose="List all recovery points with fresh checksum verification and "
                "malicious-indicator scan results.",
        input_schema=_obj({}),
        output_schema=_obj({"snapshots": {"type": "array"}}),
        handler=_query_backup_catalog, risk_level=LOW, timeout_s=30.0))

    registry.register(ToolSpec(
        name="run_service_health_check",
        purpose="Health-check one named asset or every service/identity component.",
        input_schema=_obj({"asset_name": {"type": "string"}}),
        output_schema=_obj({"healthy": {"type": "boolean"}, "checks": {"type": "array"}}),
        handler=_run_service_health_check, risk_level=LOW, timeout_s=30.0))

    registry.register(ToolSpec(
        name="run_business_transaction_test",
        purpose="Execute the end-to-end business transaction probe: login -> browse "
                "-> add-to-cart -> checkout -> order created.",
        input_schema=_obj({}),
        output_schema=_obj({"passed": {"type": "boolean"}}),
        handler=_run_business_transaction_test, risk_level=MEDIUM, timeout_s=60.0))


__all__ = ["register_recovery_tools", "validate_payload"]
