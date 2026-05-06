"""
Trilha de auditoria à prova de adulteração (hash chain).

A cada ação crítica (login, criação de usuário, ingestão, alteração
de configuração), gravamos uma linha em audit_logs com:

    row_hash = sha256(prev_hash || canonical(linha))

Verificação periódica (cron) recalcula a cadeia — se algum valor mudou,
o hash não bate.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import session_scope
from app.models.audit import AuditLog, SuspiciousEvent

logger = structlog.get_logger("app.audit")

_chain_lock = threading.Lock()


def _canonical(d: dict[str, Any]) -> str:
    """Serialização determinística para hashing."""
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


async def _last_hash(session: AsyncSession) -> Optional[str]:
    return await session.scalar(
        select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
    )


def _hash_body(prev: Optional[str], row: dict[str, Any]) -> str:
    return hashlib.sha256(((prev or "") + _canonical(row)).encode()).hexdigest()


async def write_audit(
    session: AsyncSession,
    *,
    action: str,
    resource: str,
    outcome: str,
    actor_pseudonym: Optional[str] = None,
    actor_role: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> AuditLog:
    """Grava uma entrada na cadeia de auditoria.

    Lock evita corrida que poderia gerar dois logs com o mesmo prev_hash.
    O hash NÃO inclui created_at (timestamp DB) para evitar divergência
    entre application clock e DB clock — o sequenciamento via prev_hash
    já é prova de ordem.
    """
    with _chain_lock:
        prev = await _last_hash(session)
        body = {
            "action": action,
            "resource": resource,
            "resource_id": resource_id,
            "outcome": outcome,
            "actor": actor_pseudonym,
            "role": actor_role,
            "ip": ip,
            "ua": (user_agent or "")[:255] or None,
            "rid": request_id,
            "detail": detail,
        }
        digest = _hash_body(prev, body)
        entry = AuditLog(
            actor_pseudonym=actor_pseudonym,
            actor_role=actor_role,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip,
            user_agent=(user_agent or "")[:255] or None,
            request_id=request_id,
            outcome=outcome,
            detail=detail,
            row_hash=digest,
            prev_hash=prev,
        )
        session.add(entry)
        await session.flush()
        # Eco para o stream de logs (correlação com SIEM)
        logger.info(
            "audit",
            action=action,
            resource=resource,
            outcome=outcome,
            actor=actor_pseudonym,
            request_id=request_id,
        )
    return entry


async def verify_chain(session: AsyncSession) -> tuple[bool, Optional[int]]:
    """Recalcula toda a cadeia. Retorna (ok, id_da_primeira_inconsistencia)."""
    prev = None
    rows = await session.scalars(select(AuditLog).order_by(AuditLog.id.asc()))
    for row in rows:
        body = {
            "action": row.action,
            "resource": row.resource,
            "resource_id": row.resource_id,
            "outcome": row.outcome,
            "actor": row.actor_pseudonym,
            "role": row.actor_role,
            "ip": row.ip_address,
            "ua": row.user_agent,
            "rid": row.request_id,
            "detail": row.detail,
        }
        expected = _hash_body(prev, body)
        if expected != row.row_hash or (prev != row.prev_hash):
            return False, row.id
        prev = row.row_hash
    return True, None


async def record_suspicious_event(
    *,
    kind: str,
    severity: str,
    actor_pseudonym: Optional[str] = None,
    ip: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    async with session_scope() as session:
        session.add(
            SuspiciousEvent(
                kind=kind,
                severity=severity,
                actor_pseudonym=actor_pseudonym,
                ip_address=ip,
                detail=detail,
            )
        )
    logger.warning(
        "suspicious_event",
        kind=kind,
        severity=severity,
        actor=actor_pseudonym,
        ip=ip,
    )


def record_suspicious_event_sync_safe(**kwargs) -> None:
    """Schedula a gravação sem bloquear o handler de erro síncrono."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(record_suspicious_event(**kwargs))
        else:
            loop.run_until_complete(record_suspicious_event(**kwargs))
    except Exception:  # noqa: BLE001 — best effort
        logger.warning("suspicious_event_record_failed", **kwargs)
