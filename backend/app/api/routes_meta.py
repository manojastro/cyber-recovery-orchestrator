"""Meta, health, readiness routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_db
from app.db import check_connection
from app.schemas import MetaResponse

router = APIRouter(tags=["meta"])


@router.get("/api/v1/meta", response_model=MetaResponse)
def meta(request: Request) -> MetaResponse:
    settings = request.app.state.settings
    return MetaResponse(
        app=settings.app_name,
        version=settings.version,
        llm_mode=settings.llm_mode,
        mock=settings.is_mock_llm,
        database=request.app.state.engine.url.get_backend_name(),
        cors_origins=settings.cors_origin_list,
        time=utcnow_iso(),
    )


def utcnow_iso():
    from app.util import utcnow
    return utcnow()


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/readiness")
def readiness(session: Session = Depends(get_db)) -> dict:
    ok = check_connection(session)
    return {"status": "ready" if ok else "degraded", "database": ok}
