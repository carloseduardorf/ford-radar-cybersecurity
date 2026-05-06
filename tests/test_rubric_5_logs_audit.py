"""
Rubric 5 — Monitoramento, Logs e Auditoria (15 pts)

✓ Logs estruturados e seguros (sem dados sensíveis)
✓ Monitoramento de eventos suspeitos (failed login burst, rate-limit hit)
✓ Trilha de auditoria de ações críticas (com hash chain)
"""
import io
import json

import pytest
import structlog
from sqlalchemy import select

from app.audit.service import verify_chain, write_audit
from app.logging_config import REDACT, configure_logging
from app.models.audit import AuditLog


# ─────────────────────── Redação de PII em logs ─────────────────


def test_log_redacts_password_and_email():
    """Configurar logging em modo capturable e verificar redação."""
    buf = io.StringIO()

    structlog.reset_defaults()
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            __import__("app.logging_config", fromlist=["_redact_event"])._redact_event,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(file=buf),
        cache_logger_on_first_use=False,
    )

    log = structlog.get_logger()
    log.info(
        "auth.attempt",
        email="user@example.com",
        password="SuperSecret!2026",
        access_token="eyJabc.def.ghi",
        nested={"authorization": "Bearer xyz"},
    )

    out = buf.getvalue()
    assert "SuperSecret" not in out
    assert "user@example.com" not in out
    assert "eyJabc.def.ghi" not in out
    assert REDACT in out

    # Restaurar config padrão para os outros testes
    configure_logging()


# ─────────────────────── Trilha de auditoria ───────────────────


@pytest.mark.asyncio
async def test_audit_login_recorded(client, admin_user, session):
    await client.post(
        "/v1/auth/login",
        json={"email": "admin-test@ford-test.com", "password": "AdminPass!2026FordX"},
    )
    rows = (await session.scalars(
        select(AuditLog).where(AuditLog.action == "auth.login")
    )).all()
    assert len(rows) >= 1
    success = [r for r in rows if r.outcome == "success"]
    assert success
    # Audit guarda pseudônimo, não email real
    for r in success:
        assert r.actor_pseudonym
        assert "@" not in (r.actor_pseudonym or "")


@pytest.mark.asyncio
async def test_audit_failed_login_recorded(client, admin_user, session):
    await client.post(
        "/v1/auth/login",
        json={"email": "admin-test@ford-test.com", "password": "WrongPassword!12"},
    )
    rows = (await session.scalars(
        select(AuditLog).where(AuditLog.action == "auth.login", AuditLog.outcome == "denied")
    )).all()
    assert len(rows) >= 1


@pytest.mark.asyncio
async def test_audit_chain_integrity(session):
    """Cadeia de hashes válida em condição normal."""
    await write_audit(
        session,
        action="test.chain",
        resource="t",
        outcome="success",
        actor_pseudonym="abc",
    )
    await write_audit(
        session,
        action="test.chain",
        resource="t",
        outcome="success",
        actor_pseudonym="abc",
    )
    await session.commit()
    ok, broken_at = await verify_chain(session)
    assert ok, f"chain quebrada em {broken_at}"


@pytest.mark.asyncio
async def test_audit_chain_detects_tampering(session):
    """Adulterar uma linha quebra a cadeia."""
    e1 = await write_audit(
        session,
        action="test.tamper",
        resource="t",
        outcome="success",
        actor_pseudonym="x",
    )
    e2 = await write_audit(
        session,
        action="test.tamper",
        resource="t",
        outcome="success",
        actor_pseudonym="y",
    )
    await session.commit()
    # Tamper: muda a action sem recalcular hash
    e1.action = "tampered.action"
    await session.commit()

    ok, broken_at = await verify_chain(session)
    assert not ok
    assert broken_at == e1.id


# ─────────────────────── Eventos suspeitos ─────────────────────


@pytest.mark.asyncio
async def test_rate_limit_hit_recorded_as_suspicious(client, session):
    """Estourar rate limit em /login deve gerar SuspiciousEvent."""
    from app.models.audit import SuspiciousEvent

    payload = {"email": "trash@ford-test.com", "password": "Whatever!2026XX"}
    for _ in range(8):
        await client.post("/v1/auth/login", json=payload)

    rows = (await session.scalars(
        select(SuspiciousEvent).where(SuspiciousEvent.kind == "rate_limit_exceeded")
    )).all()
    assert len(rows) >= 1


@pytest.mark.asyncio
async def test_request_id_propagated(client):
    """Cada request retorna X-Request-Id — base de correlação log/audit."""
    r = await client.get("/healthz")
    assert "X-Request-Id" in r.headers


@pytest.mark.asyncio
async def test_request_id_generated_when_invalid(client):
    """Cliente fornece request-id inválido → servidor gera novo."""
    r = await client.get("/healthz", headers={"X-Request-Id": "not-a-uuid; DROP TABLE"})
    rid = r.headers.get("X-Request-Id")
    # Servidor descartou e gerou um novo válido
    import uuid

    uuid.UUID(rid)  # não levanta
