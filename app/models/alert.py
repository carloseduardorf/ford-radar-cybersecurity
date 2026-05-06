"""Alertas competitivos gerados pela IA."""
from __future__ import annotations

import enum

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, EncryptedStr


class AlertSeverity(str, enum.Enum):
    info = "info"
    media = "media"
    alta = "alta"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    competitor_id: Mapped[int] = mapped_column(
        ForeignKey("competitors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    severity: Mapped[str] = mapped_column(String(8), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # preco|versao|potencia
    # Texto narrativo da IA — cifrado por ser conteúdo estratégico
    message_encrypted: Mapped[str] = mapped_column(EncryptedStr(), nullable=False)
