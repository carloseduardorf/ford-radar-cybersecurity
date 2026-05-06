"""Leitura de concorrentes e scores."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import CurrentUser, get_current_user
from app.database import get_session
from app.models.competitor import Competitor, CompetitorScore
from app.schemas.competitor import (
    CompetitorListQuery,
    CompetitorOut,
    ScoreOut,
)

router = APIRouter(prefix="/v1", tags=["competitors"])


@router.get("/competitors", response_model=List[CompetitorOut])
async def list_competitors(
    q: CompetitorListQuery = Depends(),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Lista concorrentes — usa queries parametrizadas (defesa SQLi)."""
    stmt = select(Competitor)
    if q.brand:
        stmt = stmt.where(Competitor.brand == q.brand)
    if q.model:
        stmt = stmt.where(Competitor.model == q.model)
    if q.year:
        stmt = stmt.where(Competitor.year == q.year)
    stmt = stmt.order_by(Competitor.id).offset((q.page - 1) * q.page_size).limit(q.page_size)
    rows = (await session.scalars(stmt)).all()
    return rows


@router.get("/scores", response_model=List[ScoreOut])
async def list_scores(
    competitor_id: int | None = Query(default=None, ge=1, le=10_000_000),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(CompetitorScore)
    if competitor_id is not None:
        stmt = stmt.where(CompetitorScore.competitor_id == competitor_id)
    stmt = stmt.order_by(CompetitorScore.id.desc()).limit(200)
    return (await session.scalars(stmt)).all()
