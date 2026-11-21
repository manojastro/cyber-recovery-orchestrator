"""API tests: health/meta/seed/incident/approve/reject paths, validation errors,
static SPA, metrics endpoint, fault-injection route."""
from __future__ import annotations


def test_health_and_readiness(client):
    assert client.get("/health").json() == {"status": "ok"}
    readiness = client.get("/readiness").json()
    assert readiness["status"] == "ready" and readiness["database"] is True


def test_meta_reports_mock_mode(client):
    meta = client.get("/api/v1/meta").json()
    assert meta["llm_mode"] == "mock"
    assert meta["mock"] is True
    assert meta["database"] == "sqlite"


def test_seed_endpoint_is_destructive_reset(client):
    first = client.post("/api/v1/simulator/seed", json={"scenario": "standard"})
    assert first.status_code == 200
    second = client.post("/api/v1/simulator/seed", json={"scenario": "standard"})
    assert second.status_code == 200
    assets = client.get("/api/v1/assets").json()
    assert len(assets) == 10


def test_full_api_happy_path(client):
    seed = client.post("/api/v1/simulator/seed", json={})
    assert seed.status_code == 200

    trigger = client.post("/api/v1/incidents/trigger", json={"scenario": "standard"})
    assert trigger.status_code == 200
    body = trigger.json()
    assert body["status"] == "detected"
    investigation_id = body["investigation_public_id"]

    run = client.post(f"/api/v1/investigations/{investigation_id}/run")
    assert run.status_code == 200
    assert run.json()["status"] == "awaiting_approval"

    approvals = client.get("/api/v1/approvals").json()
    pending = [a for a in approvals if a["status"] == "pending"]
    assert len(pending) == 1
    approval_id = pending[0]["public_id"]

    approved = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"decided_by": "ops-lead", "note": "go"})
    assert approved.status_code == 200

    executed = client.post(f"/api/v1/investigations/{investigation_id}/execute")
    assert executed.status_code == 200
    assert executed.json()["status"] == "COMPLETED"

    bundle = client.get(
        f"/api/v1/investigations/{investigation_id}").json()
    assert bundle["current_state"] == "COMPLETED"
    kinds = [d["kind"] for d in bundle["decisions"]]
    assert "recovery_point_selection" in kinds and "recovery_plan" in kinds
    outcome = bundle["outcomes"][-1]
    assert outcome["clean_point_label"] == "BKP-007"
    assert outcome["dependency_order_correct"] is True
    validations = bundle["validations"]
    assert all(v["passed"] for v in validations if v["phase"] == "post_restore")


def test_reject_path_via_http_terminates(client):
    client.post("/api/v1/simulator/seed", json={})
    trigger = client.post("/api/v1/incidents/trigger", json={})
    investigation_id = trigger.json()["investigation_public_id"]
    client.post(f"/api/v1/investigations/{investigation_id}/run")
    approval_id = [a for a in client.get("/api/v1/approvals").json()
                   if a["status"] == "pending"][0]["public_id"]

    rejected = client.post(f"/api/v1/approvals/{approval_id}/reject",
                           json={"decided_by": "ciso", "note": "not yet"})
    assert rejected.status_code == 200
    bundle = client.get(f"/api/v1/investigations/{investigation_id}").json()
    assert bundle["current_state"] == "FAILED"
    assert all(a["status"] == "cancelled" for a in bundle["actions"])

    # execution after rejection must be refused
    refused = client.post(f"/api/v1/investigations/{investigation_id}/execute")
    assert refused.status_code == 409


def test_bad_scenario_rejected_with_422(client):
    response = client.post("/api/v1/incidents/trigger",
                           json={"scenario": "nuclear_meltdown"})
    assert response.status_code == 422


def test_approval_requires_decided_by(client):
    client.post("/api/v1/simulator/seed", json={})
    trigger = client.post("/api/v1/incidents/trigger", json={})
    inv = trigger.json()["investigation_public_id"]
    client.post(f"/api/v1/investigations/{inv}/run")
    approval_id = [a for a in client.get("/api/v1/approvals").json()
                   if a["status"] == "pending"][0]["public_id"]

    missing = client.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    assert missing.status_code == 422
    too_short = client.post(f"/api/v1/approvals/{approval_id}/approve",
                            json={"decided_by": "x"})
    assert too_short.status_code == 422


def test_unknown_resources_return_404(client):
    assert client.get("/api/v1/investigations/nope").status_code == 404
    assert client.get("/api/v1/incidents/nope").status_code == 404
    assert client.get("/api/v1/backups/BKP-999").status_code == 404
    assert client.get("/api/v1/approvals/nope").status_code == 404


def test_metrics_endpoint_prometheus_format(client):
    client.post("/api/v1/simulator/seed", json={})
    text = client.get("/metrics").text
    assert "cro_tool_calls_total" in text
    assert "# HELP" in text or "# TYPE" in text


def test_spa_served_at_root(client):
    index = client.get("/")
    assert index.status_code == 200
    assert "text/html" in index.headers["content-type"]
    assert "Cyber Recovery Orchestrator" in index.text


def test_tool_catalog_endpoint(client):
    tools = client.get("/api/v1/tools/list").json()["tools"]
    names = {t["name"] for t in tools}
    assert "restore_database_snapshot" in names
    for tool in tools:
        assert {"name", "purpose", "input_schema", "risk_level"} <= set(tool)


def test_evaluation_endpoint_passes(client):
    result = client.post("/api/v1/evaluation/run",
                         json={"scenario": "corrupted_latest"})
    assert result.status_code == 200
    payload = result.json()
    assert payload["passed"] is True
    runs = client.get("/api/v1/evaluation/runs").json()
    assert len(runs) == 1 and runs[0]["passed"] is True


def test_fault_injection_route_and_rollback_flow(client):
    client.post("/api/v1/simulator/seed", json={})
    trigger = client.post("/api/v1/incidents/trigger", json={})
    inv = trigger.json()["investigation_public_id"]
    client.post(f"/api/v1/investigations/{inv}/run")

    armed = client.post("/api/v1/debug/faults",
                        json={"kind": "post_validation_failure",
                              "investigation_id": inv})
    assert armed.status_code == 200

    approval_id = [a for a in client.get("/api/v1/approvals").json()
                   if a["status"] == "pending"][0]["public_id"]
    client.post(f"/api/v1/approvals/{approval_id}/approve",
                json={"decided_by": "ops-lead"})
    executed = client.post(f"/api/v1/investigations/{inv}/execute")
    assert executed.json()["status"] == "FAILED"

    rolled = client.post(f"/api/v1/investigations/{inv}/rollback")
    assert rolled.status_code == 200
    bundle = client.get(f"/api/v1/investigations/{inv}").json()
    assert bundle["current_state"] == "ROLLED_BACK"

    bad_kind = client.post("/api/v1/debug/faults",
                           json={"kind": "explode_datacenter",
                                 "investigation_id": inv})
    assert bad_kind.status_code == 422
