"""Metadados de planilhas ingeridas (sem armazenar bytes raw cifrados)."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SpreadsheetIngest(Base):
    """Histórico de planilhas processadas pelo pipeline."""

    __tablename__ = "spreadsheet_ingests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    rows_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    submitted_by_pseudonym: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="received")
    error_message: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
