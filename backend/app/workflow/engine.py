"""Framework-neutral persisted workflow stage machine.

States (enforced server-side):
    DETECTED -> INVESTIGATING -> DIAGNOSED -> PLANNED -> VALIDATING
             -> AWAITING_APPROVAL -> APPROVED -> EXECUTING -> VERIFYING
             -> COMPLETED | FAILED -> ROLLED_BACK

Recovery execution ALWAYS pauses at AWAITING_APPROVAL. Approve moves the run to
APPROVED (execution is then triggered explicitly); reject terminates the run
cleanly with no actions executed.

LangGraph adapter note: each entry in STAGES maps 1:1 onto a LangGraph node
(node name == stage name); `TRANSITIONS` is the conditional-edge table. The
human gate is a LangGraph `interrupt_before=["execution"]` on the
AWAITING_APPROVAL node; state persistence here (investigations.current_state +
stage_runs rows) plays the role of a checkpointer, so wrapping this engine in a
LangGraph StateGraph only requires passing StageContext through node functions.
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.agents import (
    backup_integrity,
    business_criticality,
    dependency_analysis,
    diagnosis,
    incident_scope,
    planner,
    recovery_point,
    risk as risk_agent,
    validation_agent,
)
from app.config import Settings
from app.llm.provider import LLMProvider, get_provider
from app.metrics import (
    APPROVALS,
    CLEAN_POINT_ACCURACY,
    INCIDENTS_DETECTED,
    ORDERING_CORRECTNESS,
    RECOVERY_RESULTS,
    RPO_GAUGE,
    RTO_GAUGE,
    WORKFLOW_DURATION,
)
from app.models import (
    Action,
    Approval,
    Decision,
    Investigation,
    MetricSnapshot,
    Outcome,
    StageRun,
)
from app.graph.dependency_graph import build_graph_from_db, is_valid_execution_order
from app.lab.state import capture_pre_state, restore_pre_state
from app.tools.base import ToolRegistry, build_default_registry
from app.util import deterministic_id, utcnow

logger = logging.getLogger(__name__)

DETECTED = "DETECTED"
INVESTIGATING = "INVESTIGATING"
DIAGNOSED = "DIAGNOSED"
PLANNED = "PLANNED"
VALIDATING = "VALIDATING"
AWAITING_APPROVAL = "AWAITING_APPROVAL"
APPROVED = "APPROVED"
EXECUTING = "EXECUTING"
VERIFYING = "VERIFYING"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
ROLLED_BACK = "ROLLED_BACK"

TERMINAL_STATES = {COMPLETED, FAILED, ROLLED_BACK}

# stage name -> (from_state, to_state)
STAGES: List[tuple] = [
    ("incident_scope", DETECTED, INVESTIGATING),
    ("dependency_analysis", INVESTIGATING, INVESTIGATING),
    ("backup_integrity", INVESTIGATING, INVESTIGATING),
    ("recovery_point_selection", INVESTIGATING, INVESTIGATING),
    ("diagnosis", INVESTIGATING, DIAGNOSED),
    ("business_criticality", DIAGNOSED, DIAGNOSED),
    ("recovery_planning", DIAGNOSED, PLANNED),
    ("risk_assessment", PLANNED, PLANNED),
    ("pre_flight_validation", PLANNED, VALIDATING),
]

TRANSITIONS: Dict[str, set] = {
    DETECTED: {INVESTIGATING},
    INVESTIGATING: {INVESTIGATING, DIAGNOSED},
    DIAGNOSED: {DIAGNOSED, PLANNED},
    PLANNED: {PLANNED, VALIDATING, FAILED},
    VALIDATING: {AWAITING_APPROVAL},
    AWAITING_APPROVAL: {APPROVED, FAILED},  # FAILED here == rejected by human
    APPROVED: {EXECUTING},
    EXECUTING: {VERIFYING, FAILED},
    VERIFYING: {COMPLETED, FAILED},
    FAILED: {ROLLED_BACK},
    COMPLETED: set(),
    ROLLED_BACK: set(),
}

# Resolved lazily via module attributes so tests can patch agent functions.
STAGE_FUNCS: Dict[str, tuple] = {
    "incident_scope": (incident_scope, "run"),
    "dependency_analysis": (dependency_analysis, "run"),
    "backup_integrity": (backup_integrity, "run"),
    "recovery_point_selection": (recovery_point, "run"),
    "diagnosis": (diagnosis, "run"),
    "business_criticality": (business_criticality, "run"),
    "recovery_planning": (planner, "run"),
    "risk_assessment": (risk_agent, "run"),
    "pre_flight_validation": (validation_agent, "run_pre_flight"),
}


class WorkflowError(Exception):
    pass


class InvalidTransition(WorkflowError):
    pass


class WorkflowEngine:
    def __init__(self, session: Session, settings: Settings,
                 llm: Optional[LLMProvider] = None,
                 registry: Optional[ToolRegistry] = None):
        self.session = session
        self.settings = settings
        self.llm = llm or get_provider(settings)
        self.registry = registry or build_default_registry()

    # ------------------------------------------------------------ transitions

    def transition(self, investigation: Investigation, new_state: str,
                   failure_reason: Optional[str] = None) -> None:
        allowed = TRANSITIONS.get(investigation.current_state, set())
        if new_state not in allowed:
            raise InvalidTransition(
                f"illegal transition {investigation.current_state} -> {new_state}")
        investigation.updated_at = utcnow()
        if failure_reason:
            investigation.failure_reason = failure_reason
        if new_state in TERMINAL_STATES:
            investigation.closed_at = utcnow()
            from app.models import Incident
            incident = self.session.query(Incident).filter(
                Incident.public_id == investigation.incident_public_id).first()
            if incident and new_state in (COMPLETED, ROLLED_BACK):
                incident.status = "closed"
                incident.closed_at = utcnow()
            elif incident and new_state == FAILED:
                incident.status = "contained"
        investigation.current_state = new_state
        self.session.commit()
        logger.info("investigation %s -> %s", investigation.public_id, new_state)

    def _record_stage(self, investigation: Investigation, seq: int, stage: str,
                      from_state: str, to_state: str) -> StageRun:
        row = StageRun(investigation_id=investigation.id, seq=seq, stage=stage,
                       from_state=from_state, to_state=to_state, status="running",
                       started_at=utcnow(), llm_mode=self.settings.llm_mode)
        self.session.add(row)
        self.session.commit()
        return row

    def run_stage(self, investigation: Investigation, stage: str) -> dict:
        stages_by_name = {name: (frm, to) for name, frm, to in STAGES}
        if stage not in stages_by_name:
            raise WorkflowError(f"unknown stage: {stage}")
        from_state, to_state = stages_by_name[stage]
        if investigation.current_state != from_state:
            raise InvalidTransition(
                f"stage '{stage}' expects state {from_state} but investigation is "
                f"{investigation.current_state}")

        existing = self.session.query(StageRun).filter(
            StageRun.investigation_id == investigation.id,
            StageRun.stage == stage).count()
        if existing:
            raise WorkflowError(f"stage '{stage}' already executed for this "
                                "investigation")

        module, func_name = STAGE_FUNCS[stage]
        stage_func: Callable = getattr(module, func_name)

        seq = (self.session.query(StageRun).filter(
            StageRun.investigation_id == investigation.id).count() + 1)
        row = self._record_stage(investigation, seq, stage, from_state, to_state)

        ctx = _stage_context(self, investigation)
        started = time.perf_counter()
        try:
            output = stage_func(ctx) or {}
            duration_s = time.perf_counter() - started
            row.status = "completed"
            row.finished_at = utcnow()
            row.duration_ms = duration_s * 1000.0
            row.output = output
            row.llm_latency_ms = float(output.get("llm_latency_ms", 0.0)) or \
                _last_llm_latency(output)
            self.transition(investigation, to_state)
            from app.metrics import observe_stage
            observe_stage(stage, duration_s)
            return output
        except Exception as exc:
            row.status = "failed"
            row.error = str(exc)[:2000]
            row.finished_at = utcnow()
            row.duration_ms = (time.perf_counter() - started) * 1000.0
            self.session.commit()
            raise

    def run_to_approval(self, investigation: Investigation) -> dict:
        """Drive analysis stages until the mandatory human approval gate.

        Resumable: accepts a fresh DETECTED investigation or one that is part-way
        through the analysis stages; skips already-executed stages."""
        if investigation.current_state in TERMINAL_STATES or \
                investigation.current_state in (APPROVED, EXECUTING, VERIFYING):
            raise InvalidTransition(
                f"run_to_approval cannot start from {investigation.current_state}")
        started = time.perf_counter()
        outputs: Dict[str, dict] = {}
        executed_stages = {
            row.stage for row in self.session.query(StageRun).filter(
                StageRun.investigation_id == investigation.id)}
        for stage_name, _, _ in STAGES:
            if investigation.current_state == AWAITING_APPROVAL:
                break
            if stage_name in executed_stages:
                continue
            outputs[stage_name] = self.run_stage(investigation, stage_name)

        if investigation.current_state == VALIDATING:
            plan_decision = self.session.query(Decision).filter(
                Decision.investigation_id == investigation.id,
                Decision.kind == "recovery_plan").first()
            approval = Approval(
                public_id=deterministic_id("approval", investigation.public_id),
                investigation_id=investigation.id,
                decision_id=plan_decision.public_id if plan_decision else None,
                status="pending", requested_by="system:recovery-planner",
                requested_at=utcnow())
            self.session.add(approval)
            self.transition(investigation, AWAITING_APPROVAL)
        else:
            pending = self.session.query(Approval).filter(
                Approval.investigation_id == investigation.id,
                Approval.status == "pending").order_by(Approval.id.desc()).first()
            if pending is None:
                raise InvalidTransition(
                    f"workflow stopped at {investigation.current_state} without a "
                    "pending approval")
            approval = pending

        WORKFLOW_DURATION.labels(phase="to_approval").observe(
            time.perf_counter() - started)
        return {"state": investigation.current_state, "stages": outputs,
                "approval_public_id": approval.public_id}

    # ------------------------------------------------------------ approvals

    def approve(self, investigation: Investigation, decided_by: str,
                note: Optional[str] = None) -> Approval:
        approval = self._pending_approval(investigation)
        self.transition(investigation, APPROVED)
        approval.status = "approved"
        approval.decided_by = decided_by
        approval.note = note
        approval.decided_at = utcnow()
        APPROVALS.labels(decision="approved").inc()
        self.session.commit()
        return approval

    def reject(self, investigation: Investigation, decided_by: str,
               note: Optional[str] = None) -> Approval:
        approval = self._pending_approval(investigation)
        # Terminate cleanly: NO action may execute afterwards.
        self.transition(investigation, FAILED,
                        failure_reason=f"rejected by {decided_by}"
                                       + (f": {note}" if note else ""))
        approval.status = "rejected"
        approval.decided_by = decided_by
        approval.note = note
        approval.decided_at = utcnow()
        APPROVALS.labels(decision="rejected").inc()
        session_actions = self.session.query(Action).filter(
            Action.investigation_id == investigation.id).all()
        for action in session_actions:
            action.status = "cancelled"
        outcome = Outcome(investigation_id=investigation.id, result="rejected",
                          dependency_order_correct=False,
                          details={"reason": "operator rejected recovery plan"},
                          created_at=utcnow())
        self.session.add(outcome)
        RECOVERY_RESULTS.labels(result="rejected").inc()
        self.session.commit()
        return approval

    def _pending_approval(self, investigation: Investigation) -> Approval:
        approval = self.session.query(Approval).filter(
            Approval.investigation_id == investigation.id,
            Approval.status == "pending").order_by(Approval.id.desc()).first()
        if approval is None:
            raise WorkflowError("no pending approval for this investigation")
        if investigation.current_state != AWAITING_APPROVAL:
            raise InvalidTransition(
                f"investigation must be AWAITING_APPROVAL, got "
                f"{investigation.current_state}")
        return approval

    # ------------------------------------------------------- execution path

    def execute_and_verify(self, investigation: Investigation) -> dict:
        if investigation.current_state != APPROVED:
            raise InvalidTransition(
                f"execution requires APPROVED state, got "
                f"{investigation.current_state}")
        started = time.perf_counter()

        self.transition(investigation, EXECUTING)
        # capture rollback image BEFORE mutating anything
        investigation.pre_state_json = capture_pre_state(self.session)
        self.session.commit()

        modeled_rto = 0.0
        actions = self.session.query(Action).filter(
            Action.investigation_id == investigation.id).order_by(Action.seq).all()
        execution_failed = False
        failed_action = None
        for action in actions:
            action.started_at = utcnow()
            result = self.registry.execute(
                action.tool_name, _tool_args(action),
                _tool_context(self, investigation))
            action.detail = {"status": result.status, "summary": result.summary,
                             **_safe_data(result)}
            if result.ok:
                action.status = "executed"
                action.finished_at = utcnow()
                modeled_rto += float(action.estimated_rto_seconds or 0.0)
            else:
                action.status = "failed"
                action.finished_at = utcnow()
                execution_failed = True
                failed_action = action.public_id
                break

        remaining = [a for a in actions if a.status == "pending"]
        if execution_failed:
            for action in remaining:
                action.status = "skipped"

        planned_rto = float(investigation.context.get("planned_rto_seconds", 0.0))

        if execution_failed:
            self.transition(investigation, FAILED,
                            failure_reason=f"action {failed_action} failed")
            outcome = self._write_outcome(
                investigation, result="failed", measured_rto=modeled_rto,
                planned_rto=planned_rto,
                rpo=None, clean_point=None, order_correct=False,
                details={"failed_action": failed_action})
            WORKFLOW_DURATION.labels(phase="execution").observe(
                time.perf_counter() - started)
            return {"state": investigation.current_state, "outcome": "failed"}

        # ordered-recovery legality over executed asset sequence
        graph = build_graph_from_db(self.session)
        executed_assets = list(dict.fromkeys(
            a.target_asset for a in actions if a.status == "executed"))
        order_correct = is_valid_execution_order(executed_assets, graph)

        self.transition(investigation, VERIFYING)
        verification = validation_agent.run_post_restore(
            _stage_context(self, investigation))

        clean_snapshot = investigation.context.get("clean_snapshot")
        rpo_seconds = investigation.context.get("rpo_achieved_seconds")

        if verification["passed"]:
            self.transition(investigation, COMPLETED)
            outcome = self._write_outcome(
                investigation, result="completed", measured_rto=modeled_rto,
                planned_rto=planned_rto,
                rpo=float(rpo_seconds) if rpo_seconds is not None else None,
                clean_point=clean_snapshot, order_correct=order_correct,
                details={"verification": "passed",
                         "modeled_time_note": "RTO is modeled from per-step planning "
                                              "constants; wall-clock ms are in tool_calls"})
            result_state = COMPLETED
        else:
            self.transition(investigation, FAILED,
                            failure_reason="post-restore validation failed: "
                                           + ", ".join(verification["failed_checks"]))
            outcome = self._write_outcome(
                investigation, result="failed", measured_rto=modeled_rto,
                planned_rto=planned_rto,
                rpo=float(rpo_seconds) if rpo_seconds is not None else None,
                clean_point=clean_snapshot, order_correct=order_correct,
                details={"verification": "failed",
                         "failed_checks": verification["failed_checks"]})
            result_state = FAILED

        WORKFLOW_DURATION.labels(phase="execution").observe(
            time.perf_counter() - started)
        return {"state": result_state,
                "outcome": outcome.result,
                "measured_rto_seconds": modeled_rto,
                "order_correct": order_correct}

    def rollback(self, investigation: Investigation) -> dict:
        if investigation.current_state != FAILED:
            raise InvalidTransition(
                f"rollback requires FAILED state, got {investigation.current_state}")
        if not investigation.pre_state_json:
            raise WorkflowError("no pre-recovery image captured; cannot roll back")
        restored_rows = restore_pre_state(self.session,
                                          investigation.pre_state_json)
        self.transition(investigation, ROLLED_BACK,
                        failure_reason=None)
        outcome = self.session.query(Outcome).filter(
            Outcome.investigation_id == investigation.id).order_by(
            Outcome.id.desc()).first()
        if outcome:
            outcome.result = "rolled_back"
            outcome.updated_at = utcnow()
            outcome.details = {**outcome.details,
                               "rollback": "pre-recovery image restored",
                               "restored_rows": restored_rows}
        else:
            self.session.add(Outcome(
                investigation_id=investigation.id, result="rolled_back",
                dependency_order_correct=False,
                details={"rollback": "pre-recovery image restored",
                         "restored_rows": restored_rows},
                created_at=utcnow()))
        RECOVERY_RESULTS.labels(result="rolled_back").inc()
        self.session.commit()
        return {"state": ROLLED_BACK, "restored_rows": restored_rows}

    # ------------------------------------------------------------- helpers

    def _write_outcome(self, investigation, result, measured_rto, planned_rto,
                       rpo, clean_point, order_correct, details) -> Outcome:
        outcome = Outcome(
            investigation_id=investigation.id, result=result,
            measured_rto_seconds=measured_rto, planned_rto_seconds=planned_rto,
            measured_rpo_seconds=rpo, clean_point_label=clean_point,
            dependency_order_correct=order_correct, details=details,
            created_at=utcnow())
        self.session.add(outcome)
        snapshots = [
            MetricSnapshot(investigation_id=investigation.id,
                           name="rto_actual_seconds", value=float(measured_rto or 0)),
            MetricSnapshot(investigation_id=investigation.id,
                           name="rto_planned_seconds", value=float(planned_rto or 0)),
            MetricSnapshot(investigation_id=investigation.id,
                           name="rpo_achieved_seconds", value=float(rpo or 0)),
            MetricSnapshot(investigation_id=investigation.id,
                           name="dependency_order_correct",
                           value=1.0 if order_correct else 0.0),
        ]
        for snapshot in snapshots:
            snapshot.unit = "boolean" if "correct" in snapshot.name else "s"
            snapshot.recorded_at = utcnow()
            self.session.add(snapshot)
        RECOVERY_RESULTS.labels(result=result).inc()
        if result == "completed":
            RTO_GAUGE.set(float(measured_rto or 0))
            if rpo is not None:
                RPO_GAUGE.set(float(rpo))
            ORDERING_CORRECTNESS.set(1.0 if order_correct else 0.0)
        self.session.commit()
        return outcome


def get_investigation(session: Session, public_id_or_state) -> Optional[Investigation]:
    query = session.query(Investigation)
    inv = query.filter(Investigation.public_id == public_id_or_state).first()
    if inv is None and isinstance(public_id_or_state, int):
        inv = query.filter(Investigation.id == public_id_or_state).first()
    return inv


def record_incident_detected(scenario: str) -> None:
    INCIDENTS_DETECTED.labels(scenario=scenario).inc()


def record_clean_point_accuracy(accuracy: float) -> None:
    CLEAN_POINT_ACCURACY.set(accuracy)


def _stage_context(engine: WorkflowEngine, investigation: Investigation):
    from app.agents.common import StageContext
    return StageContext(session=engine.session, investigation=investigation,
                        settings=engine.settings, llm=engine.llm,
                        registry=engine.registry)


def _tool_context(engine: WorkflowEngine, investigation: Investigation):
    from app.tools.base import ToolContext
    return ToolContext(session=engine.session,
                       investigation_id=investigation.id, actor="workflow-executor")


def _tool_args(action: Action) -> dict:
    if action.tool_name.startswith("restore_"):
        return {"snapshot_label": action.source_snapshot_label}
    if action.tool_name == "restart_service":
        return {"asset_name": action.target_asset}
    return {}


def _safe_data(result) -> dict:
    data = getattr(result, "data", {}) or {}
    return {"data": {k: v for k, v in data.items() if k != "summary"}}


def _last_llm_latency(output: dict) -> float:
    reasoning = output.get("reasoning") if isinstance(output, dict) else None
    if isinstance(reasoning, dict):
        return float(reasoning.get("latency_ms", 0.0))
    return 0.0
