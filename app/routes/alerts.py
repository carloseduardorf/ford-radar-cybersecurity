"""Leitura de alertas (decifrados on-the-fly pelo TypeDecorator)."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import CurrentUser, get_current_user
from app.database import get_session
from app.models.alert import Alert

router = APIRouter(prefix="/v1", tags=["alerts"])


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    competitor_id: int
    severity: str
    kind: str
    message: str = Field(..., alias="message_encrypted")  # decifrado pelo ORM


@router.get("/alerts", response_model=List[AlertOut])
async def list_alerts(
    severity: Optional[str] = Query(default=None, max_length=8, pattern=r"^(info|media|alta)$"),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    stmt = stmt.order_by(Alert.id.desc()).limit(200)
    return (await session.scalars(stmt)).all()
