"""Domínio do challenge: concorrentes e scores competitivos."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Competitor(Base):
    """Modelo concorrente comparado ao Ford Ranger Raptor 2024."""

    __tablename__ = "competitors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    brand: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(96), nullable=False)
    year: Mapped[int] = mapped_column(Integer, nullable=False)
    horsepower: Mapped[int] = mapped_column(Integer, nullable=False)
    price_brl: Mapped[float] = mapped_column(Float, nullable=False)
    fipe_code: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    scores: Mapped[list["CompetitorScore"]] = relationship(
        back_populates="competitor", cascade="all, delete-orphan"
    )


class CompetitorScore(Base):
    """Score competitivo (0-100) calculado pelo ML."""

    __tablename__ = "competitor_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    competitor_id: Mapped[int] = mapped_column(
        ForeignKey("competitors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    trend: Mapped[str] = mapped_column(String(16), nullable=False)  # up|stable|down
    spreadsheet_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("spreadsheet_ingests.id", ondelete="SET NULL"), nullable=True
    )

    competitor: Mapped[Competitor] = relationship(back_populates="scores")
