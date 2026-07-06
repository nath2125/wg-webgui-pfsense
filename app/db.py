"""Database engine + session helpers."""
from __future__ import annotations

import os
from collections.abc import Iterator

from sqlmodel import Session, SQLModel, create_engine

from .config import get_settings

_settings = get_settings()

# check_same_thread=False so FastAPI's threadpool can share the SQLite connection.
_connect_args = {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
engine = create_engine(_settings.database_url, echo=False, connect_args=_connect_args)


def _ensure_sqlite_dir() -> None:
    url = _settings.database_url
    if "sqlite:///" not in url:
        return
    # sqlite:////data/x.db -> /data/x.db ; sqlite:///rel.db -> rel.db
    path = url.split("sqlite:///", 1)[1]
    directory = os.path.dirname(path if path.startswith("/") else os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def init_db() -> None:
    _ensure_sqlite_dir()
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
