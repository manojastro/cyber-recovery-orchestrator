"""FastAPI application factory.

Route order matters: all API routes are registered BEFORE the StaticFiles
mount at "/" so the API always wins over the SPA fallback.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api import (
    routes_approvals,
    routes_evaluation,
    routes_incidents,
    routes_investigations,
    routes_meta,
    routes_misc,
    routes_simulator,
)
from app.config import Settings, get_settings
from app.db import init_schema, make_engine, make_session_factory
from app.metrics import TOOL_CALLS  # noqa: F401 - ensure registry warm

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.engine = make_engine(settings.database_url)
        application.state.session_factory = make_session_factory(
            application.state.engine)
        init_schema(application.state.engine)
        logger.info("startup complete: db=%s llm_mode=%s",
                    application.state.engine.url.get_backend_name(),
                    settings.llm_mode)
        yield

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    # CORS restricted by environment
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Safe error handlers: never leak internals to clients; log server-side.
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request,
                                          exc: Exception) -> JSONResponse:
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500,
                            content={"detail": "internal server error"})

    app.state.settings = settings

    # ---- API routers first -------------------------------------------------
    app.include_router(routes_meta.router)
    app.include_router(routes_simulator.router)
    app.include_router(routes_incidents.router)
    app.include_router(routes_investigations.router)
    app.include_router(routes_approvals.router)
    app.include_router(routes_misc.router)
    app.include_router(routes_evaluation.router)
    if settings.enable_fault_injection:
        app.include_router(routes_evaluation.debug_router)

    # ---- metrics endpoint (prometheus text format) -------------------------
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # ---- static SPA LAST so API wins ---------------------------------------
    if FRONTEND_DIR.exists():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True),
                  name="spa")
    else:  # pragma: no cover - frontend always shipped in repo
        logger.warning("frontend dir not found at %s", FRONTEND_DIR)

    return app


# Module-level ASGI app for `uvicorn app.main:app`.
app = create_app()
