"""Dependency ordering tests: topological legality + tier awareness."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.graph.dependency_graph import (
    build_graph_from_db,
    is_valid_execution_order,
    recovery_order,
)
from app.models import Dependency

GROUND_TRUTH = json.loads(
    (Path(__file__).resolve().parents[1] / "evaluation" / "ground_truth.json")
    .read_text(encoding="utf-8"))


@pytest.fixture()
def lab(db):
    from app.lab.state import seed_lab, wipe_all

    wipe_all(db)
    seed_lab(db, scenario="standard")
    return db


def _affected(db):
    from app.models import Asset
    return {a.name for a in db.query(Asset).filter(Asset.name != "core-networking")}


def test_graph_is_acyclic_and_typed(lab):
    graph = build_graph_from_db(lab)
    assert graph.is_acyclic()
    edge_types = {d.dep_type for d in lab.query(Dependency).all()}
    assert edge_types == {
        "SERVICE_DEPENDS_ON_DATABASE", "SERVICE_REQUIRES_IDENTITY",
        "SERVICE_REQUIRES_STORAGE", "SERVICE_CALLS_SERVICE", "SERVICE_REQUIRES_CONFIG"}


def test_recovery_order_matches_ground_truth(lab):
    graph = build_graph_from_db(lab)
    order = recovery_order(graph, _affected(lab))
    expected = GROUND_TRUTH["scenarios"]["standard"]["expected_recovery_order"]
    assert order == expected


def test_database_restores_before_dependent_services(lab):
    graph = build_graph_from_db(lab)
    order = recovery_order(graph, _affected(lab))
    assert order.index("core-postgres") < order.index("order-service")
    assert order.index("identity-service") < order.index("payment-service")
    assert order.index("config-store") < order.index("core-postgres")
    # tier rule: reporting (tier 2) comes after tier 1 business services
    assert order.index("reporting-service") > order.index("web-frontend")


def test_execution_order_validator_accepts_truth_and_rejects_swaps(lab):
    graph = build_graph_from_db(lab)
    scope = _affected(lab)
    good = recovery_order(graph, scope)
    assert is_valid_execution_order(good, graph, scope)

    # move config-store after core-postgres (its dependent)
    bad = list(good)
    source = bad.index("config-store")
    target = bad.index("core-postgres")
    bad.insert(target + 1, bad.pop(source))
    assert bad.index("config-store") > bad.index("core-postgres")
    assert not is_valid_execution_order(bad, graph, scope)

    # also: web-frontend before its dependency order-service must be illegal
    bad2 = list(good)
    s2, t2 = bad2.index("web-frontend"), bad2.index("order-service")
    bad2[s2], bad2[t2] = bad2[t2], bad2[s2]
    assert not is_valid_execution_order(bad2, graph, scope)


def test_blast_radius_includes_downstream_dependents(lab):
    graph = build_graph_from_db(lab)
    radius = graph.blast_radius({"core-postgres"})
    for service in ("order-service", "web-frontend", "reporting-service"):
        assert service in radius


def test_cycle_detection_raises():
    from app.graph.dependency_graph import DependencyGraph

    assets = {"a": {"tier": 0}, "b": {"tier": 0}}
    cyclic = DependencyGraph(assets, [("a", "b", "SERVICE_CALLS_SERVICE"),
                                      ("b", "a", "SERVICE_CALLS_SERVICE")])
    with pytest.raises(ValueError, match="cycle"):
        recovery_order(cyclic, {"a", "b"})
