"""Evaluation tests: deterministic scenarios must score 100% against the
labeled ground truth (detection, clean point, ordering, RPO bound)."""
from __future__ import annotations

import pytest

from app.evaluation.runner import load_ground_truth, run_evaluation
from app.models import EvaluationRun

THRESHOLD = 1.0  # deterministic system: no excuse for less than perfect


@pytest.mark.parametrize("scenario", ["standard", "corrupted_latest"])
def test_scenario_scores_perfect_against_ground_truth(db, settings, scenario):
    result = run_evaluation(db, settings, scenario=scenario)
    assert result["detection_correct"] is True
    assert result["clean_point_correct"] is True
    assert result["ordering_correct"] is True
    assert result["rpo_within_bound"] is True
    assert result["results"]["observed"]["execution_final_state"] == "COMPLETED"
    assert result["results"]["scores"]["clean_point_accuracy"] >= THRESHOLD
    assert result["results"]["scores"]["ordering_accuracy"] >= THRESHOLD


def test_clean_point_accuracy_is_100_percent(db, settings):
    for scenario in ("standard", "corrupted_latest"):
        result = run_evaluation(db, settings, scenario=scenario)
        assert result["clean_point_correct"], (
            f"{scenario}: chose {result['results']['observed']['chosen_clean_snapshot']}"
            f" expected {result['results']['truth']['clean_snapshot_label']}")


def test_naive_latest_never_selected(db, settings):
    for scenario in ("standard", "corrupted_latest"):
        result = run_evaluation(db, settings, scenario=scenario)
        observed = result["results"]["observed"]
        assert observed["chosen_clean_snapshot"] == "BKP-007"
        assert "BKP-008" in observed["unsafe_snapshots_flagged"]


def test_rpo_within_labeled_bound(db, settings):
    truth = load_ground_truth()["scenarios"]
    for scenario in ("standard", "corrupted_latest"):
        result = run_evaluation(db, settings, scenario=scenario)
        rpo = result["achieved_rpo_seconds"]
        assert rpo is not None
        assert rpo <= truth[scenario]["rpo_bound_seconds"]
        # and it should be close to the exact theoretical window
        assert rpo == pytest.approx(1800.0, abs=5.0)


def test_evaluation_runs_persisted(db, settings):
    run_evaluation(db, settings, scenario="standard")
    run_evaluation(db, settings, scenario="corrupted_latest")
    runs = db.query(EvaluationRun).all()
    assert len(runs) == 2
    assert all(r.passed for r in runs)
    labels = {r.scenario for r in runs}
    assert labels == {"standard", "corrupted_latest"}


def test_unknown_scenario_rejected(db, settings):
    with pytest.raises(ValueError):
        run_evaluation(db, settings, scenario="unknown_scenario")
