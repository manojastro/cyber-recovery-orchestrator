"""Workflow state machine tests: transitions, approval gate, reject termination,
execution, rollback."""
from __future__ import annotations

import pytest

from app.models import Action, Approval, Decision, Outcome, StageRun, ToolCall
from app.workflow.engine import (
    TRANSITIONS,
    InvalidTransition,
    WorkflowEngine,
    WorkflowError,
)


def _stage_chain(db, investigation) -> list:
    rows = db.query(StageRun).filter(
        StageRun.investigation_id == investigation.id).order_by(StageRun.seq).all()
    return [(r.from_state, r.to_state) for r in rows]


def test_happy_path_reaches_awaiting_approval(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    result = engine.run_to_approval(investigation)
    assert investigation.current_state == "AWAITING_APPROVAL"
    chain = _stage_chain(db, investigation)
    assert ("DETECTED", "INVESTIGATING") == chain[0]
    assert ("PLANNED", "VALIDATING") == chain[-1]
    approval = db.query(Approval).filter(
        Approval.public_id == result["approval_public_id"]).first()
    assert approval.status == "pending"


def test_full_execution_completes_with_metrics(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    engine.run_to_approval(investigation)
    engine.approve(investigation, decided_by="ops-lead", note="go")
    assert investigation.current_state == "APPROVED"
    execution = engine.execute_and_verify(investigation)

    assert execution["state"] == "COMPLETED"
    outcome = db.query(Outcome).filter(
        Outcome.investigation_id == investigation.id).order_by(
        Outcome.id.desc()).first()
    assert outcome.result == "completed"
    assert outcome.measured_rto_seconds > 0
    assert outcome.planned_rto_seconds >= outcome.measured_rto_seconds
    assert outcome.measured_rpo_seconds == pytest.approx(1800.0, abs=2.0)
    assert outcome.clean_point_label == "BKP-007"
    assert outcome.dependency_order_correct is True


def test_reject_terminates_cleanly_without_execution(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    engine.run_to_approval(investigation)
    engine.reject(investigation, decided_by="security-officer",
                  note="wait for forensics")

    assert investigation.current_state == "FAILED"
    assert "rejected" in (investigation.failure_reason or "")
    actions = db.query(Action).filter(
        Action.investigation_id == investigation.id).all()
    assert actions and all(a.status == "cancelled" for a in actions)
    # no restore tool ever ran successfully
    restore_calls = db.query(ToolCall).filter(
        ToolCall.tool_name.like("restore_%")).all()
    assert restore_calls == []
    outcome = db.query(Outcome).order_by(Outcome.id.desc()).first()
    assert outcome.result == "rejected"
    with pytest.raises(InvalidTransition):
        engine.execute_and_verify(investigation)


def test_illegal_transition_raises(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")  # DETECTED
    engine = WorkflowEngine(db, settings)
    with pytest.raises(InvalidTransition):
        engine.transition(investigation, "COMPLETED")


def test_stage_requires_matching_state(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")  # DETECTED
    engine = WorkflowEngine(db, settings)
    with pytest.raises(InvalidTransition):
        engine.run_stage(investigation, "recovery_planning")


def test_stage_cannot_run_twice(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    engine.run_stage(investigation, "incident_scope")
    # after incident_scope the state is INVESTIGATING, so a second attempt from
    # run_to_approval would skip it; force direct re-run:
    from app.workflow.engine import STAGES
    stages_map = {name: (frm, to) for name, frm, to in STAGES}
    frm, _to = stages_map["incident_scope"]
    investigation.current_state = frm  # simulate replay attack on the machine
    db.commit()
    with pytest.raises(WorkflowError, match="already executed"):
        engine.run_stage(investigation, "incident_scope")


def test_execute_requires_approved_state(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    engine.run_to_approval(investigation)
    with pytest.raises(InvalidTransition, match="APPROVED"):
        engine.execute_and_verify(investigation)


def test_double_approve_fails_after_first(db, seeded_lab, settings):
    investigation, _ = seeded_lab("standard")
    engine = WorkflowEngine(db, settings)
    engine.run_to_approval(investigation)
    engine.approve(investigation, decided_by="ops-lead")
    with pytest.raises((WorkflowError, InvalidTransition)):
        engine.approve(investigation, decided_by="ops-lead-again")


def test_transition_table_is_complete_and_terminal_states_close():
    required = {
        "DETECTED", "INVESTIGATING", "DIAGNOSED", "PLANNED", "VALIDATING",
        "AWAITING_APPROVAL", "APPROVED", "EXECUTING", "VERIFYING", "COMPLETED",
        "FAILED", "ROLLED_BACK",
    }
    assert set(TRANSITIONS) == required
    assert TRANSITIONS["COMPLETED"] == set()
    assert TRANSITIONS["ROLLED_BACK"] == set()
    assert "ROLLED_BACK" in TRANSITIONS["FAILED"]
    # execution MUST pause at the human gate
    assert TRANSITIONS["AWAITING_APPROVAL"] == {"APPROVED", "FAILED"}
