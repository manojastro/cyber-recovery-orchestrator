"""Validation tests: business transaction semantics, injected failure path,
rollback restores pre-recovery state."""
from __future__ import annotations

import pytest

from app.lab.business_txn import run_business_transaction
from app.models import Action, DbRecord, Outcome
from app.workflow.engine import WorkflowEngine


def test_business_transaction_fails_during_incident(db, seeded_lab):
    seeded_lab("standard")
    outcome = run_business_transaction(db)
    assert outcome["passed"] is False
    assert outcome["failed_step"] in ("authenticate", "authenticate_credentials",
                                      "load_storefront_config")


def test_business_transaction_passes_after_clean_recovery(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    engine.run_to_approval(investigation)
    engine.approve(investigation, decided_by="ops-lead")
    execution = engine.execute_and_verify(investigation)
    assert execution["state"] == "COMPLETED"
    post = run_business_transaction(db)
    assert post["passed"] is True
    step_names = [s["name"] for s in post["steps"]]
    assert step_names == ["authenticate", "authenticate_credentials",
                          "load_storefront_config", "browse_product", "add_to_cart",
                          "checkout_payment", "order_created"]
    # proof order row persisted and unencrypted
    from app.models import DbRecord as R
    row = db.query(R).filter(R.record_key == post["order_ref"]).first()
    assert row is not None and not row.encrypted


def test_remaining_markers_fail_post_restore_verification(db, seeded_lab, settings):
    """Partial restore: one encrypted product record survives -> recovery fails."""
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)

    original_transition = engine.transition

    def transition_with_sabotage(inv, new_state, failure_reason=None):
        if new_state == "VERIFYING":
            victim = db.query(DbRecord).filter(
                DbRecord.table_name == "products").order_by(DbRecord.id).first()
            victim.encrypted = True  # simulate a restore that missed a marker
            db.commit()
        original_transition(inv, new_state, failure_reason)

    engine.transition = transition_with_sabotage  # type: ignore[method-assign]

    engine.run_to_approval(investigation)
    engine.approve(investigation, decided_by="ops-lead")
    execution = engine.execute_and_verify(investigation)
    assert execution["state"] == "FAILED"
    outcome = db.query(Outcome).filter(
        Outcome.investigation_id == investigation.id).order_by(
        Outcome.id.desc()).first()
    assert outcome.result == "failed"
    failed_checks = outcome.details.get("failed_checks", [])
    assert any("database_integrity" in c or "business_transaction" in c
               for c in failed_checks)


def test_rollback_restores_pre_recovery_state(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)

    sabotage = {"done": False}
    original_transition = engine.transition

    def transition_with_fault(inv, new_state, failure_reason=None):
        if new_state == "VERIFYING" and not sabotage["done"]:
            investigation.context = {
                **inv.context,
                "fault_inject": {"post_validation_failure": True}}
            db.commit()
            sabotage["done"] = True
        original_transition(inv, new_state, failure_reason)

    engine.transition = transition_with_fault  # type: ignore[method-assign]

    engine.run_to_approval(investigation)
    engine.approve(investigation, decided_by="ops-lead")
    execution = engine.execute_and_verify(investigation)
    assert execution["state"] == "FAILED"

    rollback = engine.rollback(investigation)
    assert rollback["state"] == "ROLLED_BACK"
    outcome = db.query(Outcome).filter(
        Outcome.investigation_id == investigation.id).order_by(
        Outcome.id.desc()).first()
    assert outcome.result == "rolled_back"

    # pre-recovery damage is back: encrypted markers present, services down
    markers = db.query(DbRecord).filter(DbRecord.encrypted.is_(True),
                                        DbRecord.deleted.is_(False)).count()
    assert markers > 100
    txn = run_business_transaction(db)
    assert txn["passed"] is False


def test_rollback_requires_failed_state(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    with pytest.raises(Exception):
        engine.rollback(investigation)
