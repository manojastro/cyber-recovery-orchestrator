"""Prometheus metrics (module-level singletons; exposed at /metrics)."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

TOOL_CALLS = Counter(
    "cro_tool_calls_total", "Registered tool invocations", ["tool", "status"]
)
STAGE_DURATION = Histogram(
    "cro_stage_duration_seconds",
    "Workflow stage duration",
    ["stage"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
WORKFLOW_DURATION = Histogram(
    "cro_workflow_duration_seconds",
    "End-to-end workflow duration per phase",
    ["phase"],  # to_approval | execution
)
LLM_LATENCY = Histogram(
    "cro_llm_latency_seconds",
    "LLM provider latency",
    ["mode"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0),
)
LLM_RETRIES = Counter(
    "cro_llm_retries_total", "LLM provider retries", ["mode"]
)
APPROVALS = Counter("cro_approvals_total", "Approval decisions", ["decision"])  # approved|rejected
RECOVERY_RESULTS = Counter(
    "cro_recovery_results_total", "Recovery outcomes", ["result"]  # completed|failed|rolled_back|rejected
)
INCIDENTS_DETECTED = Counter(
    "cro_incidents_detected_total", "Incidents raised by the detector", ["scenario"]
)
RTO_GAUGE = Gauge("cro_measured_rto_seconds", "Last measured recovery RTO (modeled)")
RPO_GAUGE = Gauge("cro_achieved_rpo_seconds", "Last achieved RPO (data-loss window)")
CLEAN_POINT_ACCURACY = Gauge(
    "cro_clean_point_accuracy", "Clean-point accuracy from last evaluation run"
)
ORDERING_CORRECTNESS = Gauge(
    "cro_dependency_ordering_correct", "Dependency-order correctness of last executed plan"
)


def observe_stage(stage: str, duration_s: float) -> None:
    STAGE_DURATION.labels(stage=stage).observe(duration_s)


def record_tool_call(tool: str, status: str) -> None:
    TOOL_CALLS.labels(tool=tool, status=status).inc()


def record_llm_latency(mode: str, latency_s: float) -> None:
    LLM_LATENCY.labels(mode=mode).observe(latency_s)
