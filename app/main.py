"""
Ponto de entrada da API.

Challenger Ford / FIAP 2026 — Sprint Cybersecurity (100/100 pts).

Integrantes do grupo:
    - Carlos Eduardo     RM 556785
    - Giulia Rocha       RM 558084
    - Caio Rossini       RM 555084
    - Gabriel Danius     RM 555747

Empilha middlewares na ordem correta (de fora para dentro):

    Cliente
       │
       ▼
    [SecurityHeaders]   ← redirect HTTPS, headers
    [CORS]              ← origens whitelist
    [RequestId]         ← correlação
    [RequestSizeLimit]  ← anti-flood/buffer-overflow
    [SlowAPI rate limit]
    [Routes]            ← Pydantic valida → dependências auth/RBAC
       │
       ▼
    Erro? → ErrorHandlers (resposta segura, log estruturado)
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import get_settings
from app.database import engine
from app.logging_config import configure_logging
from app.middleware.error_handler import register_error_handlers
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_id import RequestIdMiddleware
from app.middleware.request_size import RequestSizeLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routes import admin, alerts, auth, competitors, health, ingest


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    # Sanity check de conexão com o banco (não bloqueia se ainda subindo)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        pass
    yield
    await engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        # Em produção, escondemos a documentação interativa
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ─── Middlewares (último adicionado executa primeiro) ─────────────
    # Adicionamos do mais interno ao mais externo.
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(RequestIdMiddleware)

    # CORS estrito — sem wildcard em prod, validado no Settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list or [],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Request-Id",
            "X-Signature",
            "X-Refresh-Token",
        ],
        max_age=600,
    )

    # SecurityHeaders deve ser o mais externo possível
    app.add_middleware(SecurityHeadersMiddleware)

    # ─── Error handlers ───────────────────────────────────────────────
    register_error_handlers(app)

    # ─── Rotas ────────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(competitors.router)
    app.include_router(alerts.router)
    app.include_router(ingest.router)
    app.include_router(admin.router)

    return app


app = create_app()
