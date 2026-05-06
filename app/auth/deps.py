"""Dependências FastAPI para auth + RBAC."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.models.token import RevokedToken
from app.models.user import User, UserRole
from app.rbac import Permission, has_permission
from app.security.jwt import TokenError, verify_token

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentUser:
    id: int
    pseudonym: str
    role: str
    jti: str


async def get_current_user(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> CurrentUser:
    """Verifica access token, revogação e estado do usuário."""
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais ausentes",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = verify_token(creds.credentials, expected_type="access")
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload["jti"]
    revoked = await session.scalar(
        select(RevokedToken.jti).where(RevokedToken.jti == jti)
    )
    if revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revogado",
        )

    user_id_str = payload["sub"]
    try:
        user_id = int(user_id_str)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sub inválido")

    user = await session.scalar(select(User).where(User.id == user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário inativo")

    # Anexar à request — útil para logging/audit
    cu = CurrentUser(id=user.id, pseudonym=user.email_pseudonym, role=user.role, jti=jti)
    request.state.current_user = cu
    return cu


def require_role(*roles: UserRole):
    """Dependência: aceita apenas os papéis listados."""
    role_values = {r.value for r in roles}

    async def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in role_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão insuficiente",
            )
        return user

    return _dep


def require_permission_dep(permission: Permission):
    async def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão insuficiente",
            )
        return user

    return _dep
