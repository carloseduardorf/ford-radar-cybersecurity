"""
Lista de tokens revogados (logout, rotação de refresh).

JWT é stateless — uma vez emitido só expira no `exp`. Para invalidar
antes (logout, comprometimento), guardamos o `jti`.

A tabela é purgada periodicamente: linhas com `expires_at < now` podem
ser removidas porque o JWT já não passa em `exp`.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    typ: Mapped[str] = mapped_column(String(8), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_pseudonym: Mapped[str] = mapped_column(String(64), nullable=False)
