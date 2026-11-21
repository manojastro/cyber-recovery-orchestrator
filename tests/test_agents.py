"""Agent tests: determinism in mock mode + decision quality."""
from __future__ import annotations

from pathlib import Path

from app.config import Settings
from app.db import init_schema, make_engine, make_session_factory
from app.models import Action, Decision

from conftest import build_case  # pytest puts tests/ on sys.path


def _run_isolated(db_path: Path) -> dict:
    url = f"sqlite:///{db_path.as_posix()}"
    settings = Settings(DATABASE_URL=url, LLM_MODE="mock")
    engine = make_engine(url)
    init_schema(engine)
    session = make_session_factory(engine)()
    try:
        investigation, _incident = build_case(session, "standard")
        from app.workflow.engine import WorkflowEngine

        workflow = WorkflowEngine(session, settings)
        workflow.run_to_approval(investigation)

        decisions = session.query(Decision).filter(
            Decision.investigation_id == investigation.id).order_by(Decision.id).all()
        actions = session.query(Action).filter(
            Action.investigation_id == investigation.id).order_by(Action.seq).all()
        return {
            "decision_kinds": [d.kind for d in decisions],
            "confidences": [d.confidence for d in decisions],
            "risk_levels": [d.risk_level for d in decisions],
            "approval_flags": [d.requires_approval for d in decisions],
            "chosen_clean_point": investigation.context.get("clean_snapshot"),
            "recovery_order": investigation.context.get("recovery_order"),
            "plan_steps": [(a.seq, a.tool_name, a.target_asset,
                            a.source_snapshot_label) for a in actions],
            "risk_score": investigation.context.get("risk_score"),
            "risk_band": investigation.context.get("risk_band"),
            "state": investigation.current_state,
        }
    finally:
        session.close()
        engine.dispose()


def test_two_identical_runs_produce_identical_decisions(tmp_path):
    first = _run_isolated(tmp_path / "run-a.db")
    second = _run_isolated(tmp_path / "run-b.db")
    assert first["state"] == "AWAITING_APPROVAL" == second["state"]
    for key in ("decision_kinds", "confidences", "risk_levels", "approval_flags",
                "chosen_clean_point", "recovery_order", "plan_steps",
                "risk_score", "risk_band"):
        assert first[key] == second[key], f"nondeterministic field: {key}"


def test_decisions_carry_evidence_and_alternatives(db, seeded_lab, settings):
    from app.workflow.engine import WorkflowEngine

    investigation, _ = seeded_lab("standard")
    WorkflowEngine(db, settings).run_to_approval(investigation)
    decisions = db.query(Decision).filter(
        Decision.investigation_id == investigation.id).all()
    kinds = [d.kind for d in decisions]
    assert "recovery_point_selection" in kinds
    clean_decision = next(d for d in decisions
                          if d.kind == "recovery_point_selection")
    assert clean_decision.evidence_ids, "clean-point decision must cite evidence"
    assert len(clean_decision.alternatives) >= 1, "rejected alternatives recorded"
    plan = next(d for d in decisions if d.kind == "recovery_plan")
    assert plan.requires_approval is True


def test_clean_point_decision_justifies_rejecting_latest(db, seeded_lab, settings):
    from app.workflow.engine import WorkflowEngine

    investigation, _ = seeded_lab("standard")
    WorkflowEngine(db, settings).run_to_approval(investigation)
    decision = db.query(Decision).filter(
        Decision.investigation_id == investigation.id,
        Decision.kind == "recovery_point_selection").first()
    assert decision.payload["selection"]["chosen_label"] == "BKP-007"
    check = decision.payload["selection"]["naive_latest_check"]
    assert check["differs_from_chosen"] is True
    assert check["naive_latest_would_reintroduce"]
