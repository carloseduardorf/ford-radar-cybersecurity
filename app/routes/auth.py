"""Endpoints de autenticação."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import write_audit
from app.auth.deps import CurrentUser, get_current_user
from app.auth.service import (
    AuthError,
    authenticate,
    issue_token_pair,
    refresh_tokens,
    revoke_token,
)
from app.config import get_settings
from app.database import get_session
from app.schemas.auth import LoginRequest, RefreshRequest, TokenResponse
from app.security.jwt import TokenError, verify_token

router = APIRouter(prefix="/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    session: AsyncSession = Depends(get_session),
):
    ip = request.client.host if request.client else None
    rid = getattr(request.state, "request_id", None)
    ua = request.headers.get("user-agent", "")[:255]
    try:
        user = await authenticate(session, payload.email, payload.password.get_secret_value())
    except AuthError as exc:
        await write_audit(
            session,
            action="auth.login",
            resource="user",
            outcome="denied",
            ip=ip,
            user_agent=ua,
            request_id=rid,
            detail=str(exc),
        )
        await session.commit()
        # Mensagem genérica — não enumeramos usuários
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

    access, refresh, ttl = issue_token_pair(user)
    await write_audit(
        session,
        action="auth.login",
        resource="user",
        resource_id=str(user.id),
        outcome="success",
        actor_pseudonym=user.email_pseudonym,
        actor_role=user.role,
        ip=ip,
        user_agent=ua,
        request_id=rid,
    )
    await session.commit()
    return TokenResponse(
        access_token=access, refresh_token=refresh, expires_in=ttl
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    payload: RefreshRequest,
    session: AsyncSession = Depends(get_session),
):
    try:
        access, refresh_t, ttl = await refresh_tokens(session, payload.refresh_token)
    except AuthError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh inválido"
        )
    return TokenResponse(access_token=access, refresh_token=refresh_t, expires_in=ttl)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Revoga o JTI do access atual e o refresh enviado em body (se houver)."""
    # Revoga access atual
    settings = get_settings()
    access_exp = int(__import__("time").time() + settings.jwt_access_ttl_min * 60)
    await revoke_token(
        session,
        jti=user.jti,
        typ="access",
        exp_ts=access_exp,
        actor=user.pseudonym,
    )

    # Tenta revogar refresh do header X-Refresh-Token (opcional)
    refresh_token = request.headers.get("x-refresh-token")
    if refresh_token:
        try:
            payload = verify_token(refresh_token, expected_type="refresh")
            await revoke_token(
                session,
                jti=payload["jti"],
                typ="refresh",
                exp_ts=int(payload["exp"]),
                actor=user.pseudonym,
            )
        except TokenError:
            pass  # ignora silenciosamente — não falar nada útil para atacante

    await write_audit(
        session,
        action="auth.logout",
        resource="user",
        resource_id=str(user.id),
        outcome="success",
        actor_pseudonym=user.pseudonym,
        actor_role=user.role,
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return None
