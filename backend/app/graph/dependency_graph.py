"""Application dependency graph (NetworkX) built from the DB.

Edge semantics: A -> B means "A depends on / calls / requires B".
Recovery ordering therefore restores targets BEFORE dependents.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

import networkx as nx
from sqlalchemy.orm import Session

from app.models import Asset, Dependency


class DependencyGraph:
    def __init__(self, assets: Dict[str, dict], edges: List[tuple]):
        self.assets = assets
        self.graph = nx.DiGraph()
        for name, meta in assets.items():
            self.graph.add_node(name, **meta)
        for src, dst, dep_type in edges:
            self.graph.add_edge(src, dst, dep_type=dep_type)

    # ---------- queries ----------

    def nodes(self) -> List[str]:
        return list(self.graph.nodes)

    def tier_of(self, asset: str) -> int:
        return int(self.graph.nodes[asset].get("tier", 99))

    def dependencies_of(self, asset: str) -> Set[str]:
        return set(self.graph.successors(asset))

    def dependents_of(self, asset: str) -> Set[str]:
        return set(self.graph.predecessors(asset))

    def blast_radius(self, seeds: Set[str]) -> Set[str]:
        """Everything that transitively depends on any seed."""
        radius: Set[str] = set(seeds)
        frontier = set(seeds)
        while frontier:
            nxt: Set[str] = set()
            for node in frontier:
                nxt |= self.dependents_of(node) - radius
            radius |= nxt
            frontier = nxt
        return radius

    def is_acyclic(self) -> bool:
        return nx.is_directed_acyclic_graph(self.graph)


def build_graph_from_db(session: Session) -> DependencyGraph:
    assets = {
        a.name: {"public_id": a.public_id, "asset_type": a.asset_type, "tier": a.tier,
                 "state": a.state, "health": a.health,
                 "data_integrity_flag": a.data_integrity_flag,
                 "criticality": a.criticality}
        for a in session.query(Asset).all()
    }
    edges = [(d.from_asset, d.to_asset, d.dep_type)
             for d in session.query(Dependency).all()]
    return DependencyGraph(assets, edges)


def recovery_order(graph: DependencyGraph, scope: Optional[Set[str]] = None) -> List[str]:
    """Deterministic recovery order.

    Rules (applied to `scope`, default all assets):
      1. lower business tier first (Tier 0 infra before Tier 1 business before
         Tier 2 supporting);
      2. within the ready set, an asset is recoverable only once every asset it
         depends on (inside scope) is already recovered - Kahn's algorithm over
         the dependency DAG;
      3. ties broken alphabetically.
    """
    scope = set(scope) if scope is not None else set(graph.nodes())
    remaining = {
        node: {dep for dep in graph.dependencies_of(node) if dep in scope}
        for node in scope
    }
    order: List[str] = []
    while remaining:
        ready = [n for n, deps in remaining.items() if not deps]
        if not ready:
            raise ValueError("dependency cycle detected; no legal recovery order")
        ready.sort(key=lambda n: (graph.tier_of(n), n))
        chosen = ready[0]
        order.append(chosen)
        del remaining[chosen]
        for deps in remaining.values():
            deps.discard(chosen)
    return order


def is_valid_execution_order(order: List[str], graph: DependencyGraph,
                             scope: Optional[Set[str]] = None) -> bool:
    """Independent legality check: every dependency of each recovered asset that
    participates in the plan must already have been recovered."""
    scope = {n for n in order} if scope is None else set(scope)
    done: Set[str] = set()
    for node in order:
        if node not in scope:
            return False
        for dep in graph.dependencies_of(node):
            if dep in scope and dep not in done:
                return False
        done.add(node)
    return len(done) == len(order)
