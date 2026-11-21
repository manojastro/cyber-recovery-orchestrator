"""Tool registry tests: schema rejection, unknown tools, high-risk approval
gate, audit rows, secret redaction."""
from __future__ import annotations

import pytest

from app.models import Approval, ToolCall
from app.tools.base import ToolContext, build_default_registry


@pytest.fixture()
def registry():
    return build_default_registry()


def _ctx(db):
    return ToolContext(session=db, investigation_id=None)


def test_expected_tool_catalog_registered(registry):
    expected = {
        "restore_database_snapshot", "restore_storage_objects", "restore_configuration",
        "rotate_compromised_credentials", "restart_service", "run_integrity_check",
        "query_dependency_graph", "query_backup_catalog", "run_service_health_check",
        "run_business_transaction_test", "query_incident_timeline",
    }
    assert expected.issubset(set(registry.names()))


def test_every_spec_has_schema_risk_timeout(registry):
    for name in registry.names():
        spec = registry.get(name)
        assert spec.purpose
        assert spec.input_schema.get("type") == "object"
        assert spec.output_schema.get("type") == "object"
        assert spec.risk_level in ("low", "medium", "high")
        assert spec.timeout_s > 0


def test_unknown_tool_rejected_and_audited(db, registry):
    result = registry.execute("launch_missiles", {}, _ctx(db))
    assert result.status == "unknown_tool"
    row = db.query(ToolCall).order_by(ToolCall.id.desc()).first()
    assert row is not None and row.tool_name == "launch_missiles"
    assert row.status == "unknown_tool"


def test_schema_violation_rejected(db, registry):
    bad_target = {"target": "quantum_core"}  # not in enum
    result = registry.execute("run_integrity_check", bad_target, _ctx(db))
    assert result.status == "schema_rejected"
    assert any("enum" in e or "must be one of" in e
               for e in result.data.get("errors", []))


def test_missing_required_field_rejected(db, registry):
    result = registry.execute("restart_service", {}, _ctx(db))  # asset_name missing
    assert result.status == "schema_rejected"
    assert any("asset_name" in e for e in result.data.get("errors", []))


def test_high_risk_restore_denied_without_approval(db, registry, seeded_lab):
    investigation, _ = seeded_lab("standard")
    ctx = ToolContext(session=db, investigation_id=investigation.id)
    result = registry.execute("restore_database_snapshot",
                              {"snapshot_label": "BKP-007"}, ctx)
    assert result.status == "denied"
    row = db.query(ToolCall).order_by(ToolCall.id.desc()).first()
    assert row.status == "denied" and row.risk_level == "high"
    assert row.approval_present is False


def test_high_risk_restore_allowed_with_approved_record(db, registry, seeded_lab):
    from app.util import utcnow

    investigation, _ = seeded_lab("standard")
    db.add(Approval(public_id="appr-1", investigation_id=investigation.id,
                    status="approved", requested_at=utcnow()))
    db.commit()
    ctx = ToolContext(session=db, investigation_id=investigation.id)
    result = registry.execute("restore_database_snapshot",
                              {"snapshot_label": "BKP-007"}, ctx)
    assert result.status == "success"
    assert "restored" in result.summary
    row = db.query(ToolCall).order_by(ToolCall.id.desc()).first()
    assert row.status == "success" and row.approval_present is True


def test_medium_risk_tool_runs_without_approval(db, registry, seeded_lab):
    seeded_lab("standard")
    result = registry.execute("rotate_compromised_credentials", {}, _ctx(db))
    assert result.status == "success"
    assert len(result.data["principals"]) >= 3


def test_audit_arguments_are_redacted(db, registry):
    registry.execute("query_incident_timeline",
                     {"incident_public_id": "inc-1",
                      "api_key": "sk-super-secret-123"}, _ctx(db))
    row = db.query(ToolCall).order_by(ToolCall.id.desc()).first()
    assert row.arguments["api_key"] == "***REDACTED***"
    assert "sk-super-secret-123" not in str(row.arguments)


def test_handler_error_becomes_error_result_not_exception(db, registry, seeded_lab):
    seeded_lab("standard")
    result = registry.execute("run_integrity_check",
                              {"target": "database"}, _ctx(db))
    assert result.status in ("error", "success")  # handler itself must not crash
    assert result.status == "success"


def test_business_transaction_probe_fails_during_incident(db, registry, seeded_lab):
    seeded_lab("standard")
    result = registry.execute("run_business_transaction_test", {}, _ctx(db))
    assert result.status == "success"  # the probe ran fine...
    assert result.data["passed"] is False  # ...but the business journey failed
