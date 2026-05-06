"""Configuração do SQLAlchemy 2.x assíncrono."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings


def _build_engine() -> AsyncEngine:
    s = get_settings()
    connect_args: dict = {}
    if s.database_url.startswith("sqlite"):
        # SQLite só pra dev/testes
        connect_args = {"check_same_thread": False}
    return create_async_engine(
        s.database_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


engine: AsyncEngine = _build_engine()
SessionLocal = async_sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    """Dependência FastAPI que injeta uma AsyncSession por request."""
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
