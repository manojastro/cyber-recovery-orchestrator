"""Evaluation runner: replays scenarios against labeled ground truth.

Computes detection correctness, clean-point accuracy, recovery-ordering
correctness and RPO-bound satisfaction; persists an EvaluationRun row.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.config import Settings
from app.lab.detector import detect_incident
from app.lab.incident import inject_ransomware
from app.lab.state import seed_lab, wipe_all
from app.models import Action, EvaluationRun, Incident, Investigation
from app.util import deterministic_id, utcnow
from app.workflow.engine import WorkflowEngine

# backend/app/evaluation/runner.py -> parents[3] == project root
ROOT = Path(__file__).resolve().parents[3]
GROUND_TRUTH_PATH = ROOT / "evaluation" / "ground_truth.json"


def load_ground_truth() -> dict:
    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_evaluation(session: Session, settings: Settings,
                   scenario: str = "standard") -> dict:
    started = time.perf_counter()
    truth_doc = load_ground_truth()
    if scenario not in truth_doc["scenarios"]:
        raise ValueError(f"unknown scenario for evaluation: {scenario}")
    truth = truth_doc["scenarios"][scenario]

    # ---- replay the full pipeline deterministically -----------------------
    # One shared clock reference so snapshot times vs compromise window are exact.
    lab_now = utcnow()
    wipe_all(session)
    session.commit()
    seed_lab(session, scenario=scenario, now=lab_now)

    incident = inject_ransomware(session, scenario=scenario, now=lab_now)
    incident = detect_incident(session, incident)
    detected_correctly = (incident.status == "open") == bool(
        truth["expected_detection"])

    investigation = Investigation(
        public_id=deterministic_id("investigation", incident.public_id),
        incident_public_id=incident.public_id, scenario=scenario,
        current_state="DETECTED",
        context={"affected_assets": [], "fault_inject": {}},
        created_at=utcnow(), updated_at=utcnow())
    session.add(investigation)
    session.commit()

    engine = WorkflowEngine(session, settings)
    # Seed scope from the same event-timeline facts the scope agent uses.
    from app.agents.common import StageContext
    from app.tools.base import ToolContext

    probe_ctx = StageContext(session=session, investigation=investigation,
                             settings=settings, llm=engine.llm,
                             registry=engine.registry)
    timeline = probe_ctx.call_tool("query_incident_timeline", {
        "incident_public_id": incident.public_id})
    affected = set()
    for event in timeline.data["events"]:
        affected.update((event.get("payload") or {}).get("assets", []))
    investigation.context = {**(investigation.context or {}),
                             "affected_assets": sorted(affected)}
    session.commit()

    engine.run_to_approval(investigation)

    approval = engine.approve(investigation, decided_by="evaluation-runner")
    execution = engine.execute_and_verify(investigation)

    # ---- scoring ----------------------------------------------------------
    chosen_clean = investigation.context.get("clean_snapshot")
    clean_point_correct = chosen_clean == truth["clean_snapshot_label"]

    executed_assets = [
        a.target_asset for a in session.query(Action).filter(
            Action.investigation_id == investigation.id,
            Action.status == "executed").order_by(Action.seq).all()]
    unique_executed = list(dict.fromkeys(executed_assets))
    expected_order = truth["expected_recovery_order"]
    ordering_matches_truth = unique_executed == expected_order
    from app.graph.dependency_graph import build_graph_from_db, is_valid_execution_order
    legality = is_valid_execution_order(unique_executed, build_graph_from_db(session))
    ordering_correct = ordering_matches_truth and legality

    rpo_seconds: Optional[float] = None
    outcome_row = None
    from app.models import Outcome as _Outcome
    outcome_row = session.query(_Outcome).filter(
        _Outcome.investigation_id == investigation.id).order_by(
        _Outcome.id.desc()).first()
    if outcome_row is not None and outcome_row.measured_rpo_seconds is not None:
        rpo_seconds = float(outcome_row.measured_rpo_seconds)
    elif investigation.context.get("rpo_achieved_seconds") is not None:
        rpo_seconds = float(investigation.context["rpo_achieved_seconds"])
    rpo_within_bound = (rpo_seconds is not None
                        and rpo_seconds <= float(truth["rpo_bound_seconds"]))

    accuracy_scores = {
        "detection_correctness": 1.0 if detected_correctly else 0.0,
        "clean_point_accuracy": 1.0 if clean_point_correct else 0.0,
        "ordering_accuracy": (1.0 if ordering_correct else
                              _partial_order_accuracy(unique_executed,
                                                      expected_order)),
        "rpo_bound_satisfied": 1.0 if rpo_within_bound else 0.0,
    }
    clean_point_accuracy = accuracy_scores["clean_point_accuracy"]
    ordering_accuracy = accuracy_scores["ordering_accuracy"]

    passed = all([
        detected_correctly,
        clean_point_correct,
        ordering_correct,
        rpo_within_bound,
        execution.get("state") == "COMPLETED",
    ])

    results_payload = {
        "truth": {
            "clean_snapshot_label": truth["clean_snapshot_label"],
            "expected_recovery_order": expected_order,
            "rpo_bound_seconds": truth["rpo_bound_seconds"],
        },
        "observed": {
            "incident_status": incident.status,
            "chosen_clean_snapshot": chosen_clean,
            "executed_order": unique_executed,
            "execution_final_state": execution.get("state"),
            "achieved_rpo_seconds": rpo_seconds,
            "unsafe_snapshots_flagged": sorted(
                e["label"] for e in (investigation.context.get(
                    "backup_evaluations") or []) if e["status"] == "failed"),
            "expected_unsafe_snapshots": truth["unsafe_snapshots"],
        },
        "scores": accuracy_scores,
    }

    duration_ms = (time.perf_counter() - started) * 1000.0
    evaluation_run = EvaluationRun(
        public_id=deterministic_id("evalrun", scenario, str(utcnow())),
        scenario=scenario, passed=passed,
        detection_correct=detected_correctly, clean_point_correct=clean_point_correct,
        ordering_correct=ordering_correct, rpo_within_bound=rpo_within_bound,
        clean_point_accuracy=clean_point_accuracy,
        ordering_accuracy=ordering_accuracy,
        achieved_rpo_seconds=rpo_seconds,
        achieved_rto_seconds=(float(outcome_row.measured_rto_seconds)
                              if outcome_row and outcome_row.measured_rto_seconds
                              else None),
        results=results_payload, duration_ms=duration_ms, created_at=utcnow())
    session.add(evaluation_run)
    session.commit()

    from app.metrics import CLEAN_POINT_ACCURACY
    CLEAN_POINT_ACCURACY.set(clean_point_accuracy)

    return {
        "evaluation_id": evaluation_run.public_id,
        "scenario": scenario,
        "passed": passed,
        "detection_correct": detected_correctly,
        "clean_point_correct": clean_point_correct,
        "ordering_correct": ordering_correct,
        "rpo_within_bound": rpo_within_bound,
        "achieved_rpo_seconds": rpo_seconds,
        "achieved_rto_seconds": evaluation_run.achieved_rto_seconds,
        "results": results_payload,
        "duration_ms": duration_ms,
    }


def _partial_order_accuracy(observed: list, expected: list) -> float:
    """Fraction of expected steps that appear at the correct index."""
    if not expected:
        return 0.0
    correct = sum(1 for idx, item in enumerate(expected)
                  if idx < len(observed) and observed[idx] == item)
    return correct / len(expected)
