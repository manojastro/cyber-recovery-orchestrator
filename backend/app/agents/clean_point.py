"""Clean-point selection algorithm (pure, deterministic).

MUST NOT blindly pick the latest snapshot. Candidates are scored on:
  - timestamp vs incident start (RPO cost of going back in time),
  - integrity verification result (checksum),
  - malicious indicators (encrypted-record markers inside the snapshot),
  - completeness.
Hard rule: any candidate failing checksum or carrying malicious indicators is
ineligible; among eligible candidates the newest (lowest RPO cost) wins.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional


def score_candidates(candidates: List[dict],
                     incident_started_at: datetime) -> List[dict]:
    """candidates: [{label, taken_at(iso), checksum_ok, indicator_count,
                     completeness, status}]. Adds score + eligibility fields."""
    ranked = sorted(candidates, key=lambda c: c["taken_at"], reverse=True)
    n = max(len(ranked), 1)
    scored: List[dict] = []
    for rank, cand in enumerate(ranked):
        taken_at = datetime.fromisoformat(cand["taken_at"])
        rpo_cost_s = max((incident_started_at - taken_at).total_seconds(), 0.0)
        violations = []
        if not cand.get("checksum_ok", False):
            violations.append("checksum_mismatch")
        if int(cand.get("indicator_count", 0)) > 0:
            violations.append("malicious_indicators")
        recency_points = 100.0 * (n - rank) / n
        completeness_points = float(cand.get("completeness", 1.0)) * 20.0
        rpo_penalty = (rpo_cost_s / 3600.0) * 5.0  # small: recency already dominates
        total = round(recency_points + completeness_points - rpo_penalty, 3)
        scored.append({
            **cand,
            "recency_rank": rank,
            "rpo_cost_seconds": rpo_cost_s,
            "violations": violations,
            "eligible": not violations,
            "score_total": total if not violations else -1000.0 + len(violations),
        })
    return scored


def select_clean_point(candidates: List[dict],
                       incident_started_at: datetime) -> dict:
    """Returns selection with chosen candidate, rejected alternatives and the
    naive-latest contrast used in the justification."""
    scored = score_candidates(candidates, incident_started_at)
    eligible = [c for c in scored if c["eligible"]]
    alternatives: List[dict] = []

    if eligible:
        chosen = max(eligible, key=lambda c: (c["score_total"], c["taken_at"]))
        band = "low"
        rationale_head = (
            f"{chosen['label']} is the newest recovery point that passes checksum "
            f"verification and carries zero malicious indicators"
        )
    else:
        # No fully clean point exists: pick the least-bad (fewest violations and
        # indicators, then most recent) but flag critical risk.
        chosen = min(scored, key=lambda c: (len(c["violations"]),
                                            c["indicator_count"], c["recency_rank"]))
        band = "critical"
        rationale_head = (
            f"NO clean recovery point exists; {chosen['label']} selected as "
            "least-bad fallback"
        )

    for cand in scored:
        if cand["label"] == chosen["label"]:
            continue
        reasons = []
        for violation in cand["violations"]:
            reasons.append(violation)
        if not reasons:
            reasons.append("older than the selected clean point (higher RPO cost)")
        alternatives.append({"label": cand["label"], "rejected_for": reasons,
                             "score_total": cand["score_total"]})

    newest = scored[0]
    naive_note = {
        "naive_latest_label": newest["label"],
        "naive_latest_would_reintroduce": newest["violations"] or "nothing",
        "differs_from_chosen": newest["label"] != chosen["label"],
    }

    return {
        "chosen_label": chosen["label"],
        "chosen_public_id": chosen.get("public_id", ""),
        "risk_band": band,
        "scored_candidates": scored,
        "alternatives_rejected": alternatives,
        "rationale_head": rationale_head,
        "rpo_achieved_seconds": chosen["rpo_cost_seconds"],
        "naive_latest_check": naive_note,
    }


def summarize_scores(scored: List[dict]) -> List[dict]:
    """Compact view for UI/API payloads."""
    return [{"label": s["label"], "status": s["status"], "eligible": s["eligible"],
             "indicator_count": s["indicator_count"], "score": s["score_total"],
             "rpo_cost_seconds": s["rpo_cost_seconds"]} for s in scored]
