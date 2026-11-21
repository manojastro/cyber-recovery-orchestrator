"""Database engine / session management (SQLAlchemy 2.x)."""
from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str) -> Engine:
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        # Ensure the parent directory of a file-based SQLite DB exists.
        path_part = database_url.split("///", 1)[-1]
        if path_part and path_part not in (":memory:",) and not database_url.startswith("sqlite:///:"):
            try:
                Path(path_part).parent.mkdir(parents=True, exist_ok=True)
            except OSError:  # pragma: no cover - defensive
                logger.warning("could not create data dir for %s", database_url)
    return create_engine(database_url, connect_args=connect_args, future=True)


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_schema(engine: Engine, base=Base) -> None:
    base.metadata.create_all(engine)


def check_connection(session: Session) -> bool:
    try:
        session.execute(text("SELECT 1"))
        return True
    except Exception:  # pragma: no cover - readiness probe
        return False
