"""Modelo de usuário com email criptografado + pseudônimo indexado."""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, EncryptedStr


class UserRole(str, enum.Enum):
    """Papéis do RBAC.

    - admin: gerencia usuários, segredos e configurações
    - analyst: acessa todos os dados competitivos, aciona ML, revisa alertas
    - user: leitura limitada (dashboards públicos internos)
    """

    admin = "admin"
    analyst = "analyst"
    user = "user"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Pseudônimo HMAC indexado — usado em logs/ML/joins sem expor email real
    email_pseudonym: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    # Email cifrado em repouso
    email_encrypted: Mapped[str] = mapped_column(EncryptedStr(), nullable=False)
    # Hash da senha (Argon2id)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default=UserRole.user.value
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Anti brute-force / lockout
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # nunca incluir email/hash aqui
        return f"<User id={self.id} pseudonym={self.email_pseudonym[:8]}... role={self.role}>"
