"""
Fixtures compartilhadas: app, DB efêmero, cliente HTTP, helpers de auth.
"""
from __future__ import annotations

import asyncio
import os
import sys

# Pre-config do ambiente ANTES de importar app.config
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_challenge.db")
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ.setdefault("PSEUDONYM_SALT", "y" * 64)
os.environ.setdefault("WEBHOOK_HMAC_SECRET", "z" * 64)
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
os.environ.setdefault("RATE_LIMIT_DEFAULT", "1000/minute")  # alto para a maioria dos testes
os.environ.setdefault("RATE_LIMIT_AUTH", "5/minute")
os.environ.setdefault("RATE_LIMIT_INGEST", "100/minute")
os.environ.setdefault("FORCE_HTTPS", "false")  # testes locais não usam TLS

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from sqlalchemy import select  # noqa: E402

from app import database as db_module  # noqa: E402
from app.auth.service import create_user  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Base  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402
from app.security.pseudonym import pseudonymize  # noqa: E402


async def _ensure_user(session, *, email: str, password: str, role: UserRole):
    """Idempotente: retorna existente ou cria."""
    pseudonym = pseudonymize(email.lower())
    user = await session.scalar(
        select(User).where(User.email_pseudonym == pseudonym)
    )
    if user:
        return user
    return await create_user(session, email=email, password=password, role=role)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _prepare_db():
    """Cria schema uma única vez por sessão de teste."""
    # Remove DB de testes prévio
    db_path = "./test_challenge.db"
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
    except OSError:
        pass

    async with db_module.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await db_module.engine.dispose()


@pytest_asyncio.fixture
async def session() -> AsyncSession:
    async with db_module.SessionLocal() as s:
        yield s


@pytest_asyncio.fixture
async def app():
    return create_app()


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest_asyncio.fixture
async def admin_user(session):
    return await _ensure_user(
        session, email="admin-test@ford-test.com",
        password="AdminPass!2026FordX", role=UserRole.admin,
    )


@pytest_asyncio.fixture
async def analyst_user(session):
    return await _ensure_user(
        session, email="analyst-test@ford-test.com",
        password="AnalystPass!2026Ford", role=UserRole.analyst,
    )


@pytest_asyncio.fixture
async def user_user(session):
    return await _ensure_user(
        session, email="reader-test@ford-test.com",
        password="ReaderPass!2026Ford", role=UserRole.user,
    )


@pytest_asyncio.fixture(autouse=True)
async def _reset_rate_limiter():
    """Limpa o storage in-memory do rate limiter entre testes."""
    from app.middleware.rate_limit import limiter

    limiter.reset()
    yield


async def _login_helper(client: AsyncClient, email: str, password: str) -> dict:
    r = await client.post("/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


@pytest_asyncio.fixture
async def admin_token(client, admin_user):
    tokens = await _login_helper(client, "admin-test@ford-test.com", "AdminPass!2026FordX")
    return tokens["access_token"]


@pytest_asyncio.fixture
async def analyst_token(client, analyst_user):
    tokens = await _login_helper(client, "analyst-test@ford-test.com", "AnalystPass!2026Ford")
    return tokens["access_token"]


@pytest_asyncio.fixture
async def user_token(client, user_user):
    tokens = await _login_helper(client, "reader-test@ford-test.com", "ReaderPass!2026Ford")
    return tokens["access_token"]
