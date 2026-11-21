"""Clean-point selection tests, including the corrupted-latest case."""
from __future__ import annotations

from datetime import datetime, timedelta

from app.agents.clean_point import score_candidates, select_clean_point

T0 = datetime(2026, 8, 24, 12, 0, 0)


def _cand(label, minutes_before_t0, checksum_ok=True, indicators=0,
          completeness=1.0):
    taken_at = T0 - timedelta(minutes=minutes_before_t0)
    status = "verified" if (checksum_ok and indicators == 0) else "failed"
    return {"label": label, "public_id": f"pub-{label}", "taken_at": taken_at.isoformat(),
            "status": status, "checksum_ok": checksum_ok,
            "indicator_count": indicators, "completeness": completeness}


def test_naive_latest_with_indicators_is_rejected():
    candidates = [
        _cand("BKP-001", 240), _cand("BKP-002", 180),
        _cand("BKP-003", 120),
        # latest snapshot was taken AFTER compromise started: encrypted markers
        _cand("BKP-004", 30, indicators=2),
    ]
    selection = select_clean_point(candidates, T0)
    assert selection["chosen_label"] == "BKP-003"
    assert selection["naive_latest_check"]["differs_from_chosen"] is True
    assert "malicious_indicators" in \
        selection["naive_latest_check"]["naive_latest_would_reintroduce"]


def test_corrupted_latest_checksum_failure_excluded():
    candidates = [
        _cand("BKP-006", 180), _cand("BKP-007", 120),
        _cand("BKP-008", 60, checksum_ok=False, indicators=2),
    ]
    selection = select_clean_point(candidates, T0)
    assert selection["chosen_label"] == "BKP-007"
    rejected = {a["label"]: a for a in selection["alternatives_rejected"]}
    assert "checksum_mismatch" in rejected["BKP-008"]["rejected_for"]
    assert rejected["BKP-006"]["rejected_for"] == [
        "older than the selected clean point (higher RPO cost)"]
    assert selection["chosen_label"] not in rejected


def test_newest_clean_point_wins_when_all_safe():
    candidates = [_cand("A", 300), _cand("B", 240), _cand("C", 90)]
    selection = select_clean_point(candidates, T0)
    assert selection["chosen_label"] == "C"
    assert selection["rpo_achieved_seconds"] == 90 * 60
    assert selection["risk_band"] == "low"


def test_no_safe_candidate_falls_back_least_bad_and_flags_critical():
    candidates = [
        _cand("X", 200, indicators=5, checksum_ok=False),
        _cand("Y", 100, indicators=1),
    ]
    selection = select_clean_point(candidates, T0)
    assert selection["risk_band"] == "critical"
    assert selection["chosen_label"] == "Y"  # fewer violations/indicators


def test_scores_are_deterministic():
    candidates = [_cand("A", 240), _cand("B", 120, indicators=1)]
    first = [c["score_total"] for c in score_candidates(candidates, T0)]
    second = [c["score_total"] for c in score_candidates(candidates, T0)]
    assert first == second
    scored = score_candidates(candidates, T0)
    by_label = {c["label"]: c for c in scored}
    assert by_label["A"]["eligible"] is True
    assert by_label["B"]["eligible"] is False
    assert by_label["B"]["score_total"] < -500  # hard penalty dominates


def test_rpo_cost_reflects_distance_to_incident():
    scored = score_candidates([_cand("OLD", 480), _cand("NEW", 60)], T0)
    by_label = {c["label"]: c for c in scored}
    assert by_label["NEW"]["rpo_cost_seconds"] == 3600.0
    assert by_label["OLD"]["rpo_cost_seconds"] == 480 * 60
    assert by_label["NEW"]["score_total"] > by_label["OLD"]["score_total"]
