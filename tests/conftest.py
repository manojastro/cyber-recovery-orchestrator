"""Shared pytest fixtures. ASCII-only output (cp1252 console safe)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.db import init_schema, make_engine, make_session_factory  # noqa: E402
from app.lab.detector import detect_incident  # noqa: E402
from app.lab.incident import inject_ransomware  # noqa: E402
from app.lab.state import seed_lab, wipe_all  # noqa: E402
from app.models import Investigation  # noqa: E402
from app.util import deterministic_id, utcnow  # noqa: E402


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        DATABASE_URL=f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        LLM_MODE="mock",
        ENABLE_FAULT_INJECTION=True,
    )


@pytest.fixture()
def db(settings):
    engine = make_engine(settings.database_url)
    init_schema(engine)
    factory = make_session_factory(engine)
    session = factory()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def client(settings):
    from app.main import create_app

    application = create_app(settings)
    with TestClient(application) as test_client:
        yield test_client


def build_case(session, scenario: str = "standard"):
    """Fresh lab + ransomware injection + detection + investigation (DETECTED).

    Module-level so isolated determinism runs can reuse it.
    """
    now = utcnow()
    wipe_all(session)
    session.commit()
    seed_lab(session, scenario=scenario, now=now)
    incident = inject_ransomware(session, scenario=scenario, now=now)
    incident = detect_incident(session, incident)
    assert incident.status == "open", "detector must raise the incident"
    investigation = Investigation(
        public_id=deterministic_id("investigation", incident.public_id),
        incident_public_id=incident.public_id, scenario=scenario,
        current_state="DETECTED",
        context={"affected_assets": [], "fault_inject": {}},
        created_at=utcnow(), updated_at=utcnow())
    session.add(investigation)
    session.commit()

    # scope facts from the timeline (same as the API/demo path)
    from app.agents.common import StageContext
    from app.tools.base import build_default_registry

    probe_ctx = StageContext(session=session, investigation=investigation,
                             settings=None, llm=None,
                             registry=build_default_registry())
    timeline = probe_ctx.call_tool("query_incident_timeline",
                                   {"incident_public_id": incident.public_id})
    affected = set()
    for event in timeline.data["events"]:
        affected.update((event.get("payload") or {}).get("assets", []))
    investigation.context = {**investigation.context,
                             "affected_assets": sorted(affected)}
    session.commit()
    return investigation, incident


@pytest.fixture()
def seeded_lab(db):
    """Returns builder for fresh lab + incident + investigation in DETECTED."""
    return lambda scenario="standard": build_case(db, scenario)


@pytest.fixture()
def workflow_factory(db, settings):
    from app.workflow.engine import WorkflowEngine

    def make():
        return WorkflowEngine(db, settings)

    return make
