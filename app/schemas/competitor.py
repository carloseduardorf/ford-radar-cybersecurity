"""Schemas do domínio competitivo."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import (
    HorsepowerInt,
    PositiveInt,
    PriceFloat,
    SafeCode,
    SafeName,
    ScoreInt,
    YearInt,
)


class CompetitorIn(BaseModel):
    """Input vindo do pipeline (planilha → ML)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    brand: SafeName
    model: SafeName
    version: SafeName
    year: YearInt
    horsepower: HorsepowerInt
    price_brl: PriceFloat
    fipe_code: Optional[SafeCode] = None


class CompetitorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    brand: str
    model: str
    version: str
    year: int
    horsepower: int
    price_brl: float
    fipe_code: Optional[str] = None


class ScoreOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    competitor_id: int
    score: float
    trend: str


class CompetitorListQuery(BaseModel):
    """Filtros do endpoint /competitors. Limites estritos contra abuso."""

    model_config = ConfigDict(extra="forbid")

    brand: Optional[SafeName] = None
    model: Optional[SafeName] = None
    year: Optional[YearInt] = None
    min_score: Optional[ScoreInt] = None
    page: PositiveInt = Field(default=1)
    page_size: int = Field(default=25, ge=1, le=100)
