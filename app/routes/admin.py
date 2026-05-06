"""Rotas administrativas (admin only): usuários, auditoria, eventos suspeitos."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import verify_chain, write_audit
from app.auth.deps import CurrentUser, require_role
from app.auth.service import AuthError, create_user
from app.database import get_session
from app.models.audit import AuditLog, SuspiciousEvent
from app.models.user import User, UserRole
from app.schemas.auth import CreateUserRequest

router = APIRouter(prefix="/v1/admin", tags=["admin"])


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email_pseudonym: str
    role: str
    is_active: bool


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    actor_pseudonym: Optional[str]
    actor_role: Optional[str]
    action: str
    resource: str
    resource_id: Optional[str]
    outcome: str
    ip_address: Optional[str]
    request_id: Optional[str]
    detail: Optional[str]
    row_hash: str
    prev_hash: Optional[str]


class SuspiciousOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    severity: str
    actor_pseudonym: Optional[str]
    ip_address: Optional[str]
    detail: Optional[str]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def admin_create_user(
    payload: CreateUserRequest,
    actor: CurrentUser = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_session),
):
    try:
        new_user = await create_user(
            session,
            email=payload.email,
            password=payload.password.get_secret_value(),
            role=UserRole(payload.role),
        )
    except AuthError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    await write_audit(
        session,
        action="user.create",
        resource="user",
        resource_id=str(new_user.id),
        outcome="success",
        actor_pseudonym=actor.pseudonym,
        actor_role=actor.role,
    )
    await session.commit()
    return new_user


@router.get("/audit", response_model=List[AuditOut])
async def list_audit(
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=50, ge=1, le=200),
    actor: CurrentUser = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_session),
):
    stmt = (
        select(AuditLog)
        .order_by(AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return (await session.scalars(stmt)).all()


@router.get("/audit/verify")
async def verify_audit_chain(
    actor: CurrentUser = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_session),
):
    ok, broken_id = await verify_chain(session)
    return {"ok": ok, "broken_at_id": broken_id}


@router.get("/suspicious", response_model=List[SuspiciousOut])
async def list_suspicious(
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=50, ge=1, le=200),
    actor: CurrentUser = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_session),
):
    stmt = (
        select(SuspiciousEvent)
        .order_by(SuspiciousEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return (await session.scalars(stmt)).all()
