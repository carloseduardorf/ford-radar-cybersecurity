"""
Trilha de auditoria à prova de adulteração (hash chain).

Cada novo log carrega ``prev_hash`` = SHA256 da linha anterior (canonicalizada).
Se um operador malicioso alterar uma linha, todos os hashes posteriores
ficam inconsistentes — detectável por verificação periódica.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_pseudonym: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)  # success|denied|error
    detail: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)

    # Hash chain
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class SuspiciousEvent(Base):
    """Eventos suspeitos detectados (failed logins burst, rate-limit hits, etc.)."""

    __tablename__ = "suspicious_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(8), nullable=False)
    actor_pseudonym: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
