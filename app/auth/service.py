"""Lógica de autenticação: login, refresh, logout, criação."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.token import RevokedToken
from app.models.user import User, UserRole
from app.security.hashing import hash_password, needs_rehash, verify_password
from app.security.jwt import TokenError, issue_token, verify_token
from app.security.pseudonym import pseudonymize


class AuthError(Exception):
    """Falha de autenticação. Mensagem genérica para não vazar enumeração."""


# Janela de lockout simples (camada extra ao rate limit IP-based)
MAX_FAILED = 5
LOCKOUT_MINUTES = 15


async def _find_user_by_email(session: AsyncSession, email: str) -> Optional[User]:
    pseudonym = pseudonymize(email.lower())
    return await session.scalar(
        select(User).where(User.email_pseudonym == pseudonym)
    )


async def authenticate(session: AsyncSession, email: str, password: str) -> User:
    """Autentica por email + senha. Mensagem genérica em qualquer falha."""
    now = datetime.now(timezone.utc)
    user = await _find_user_by_email(session, email)

    # Tempo constante: sempre fazemos uma operação de hash, mesmo se o
    # usuário não existe — evita user enumeration por timing.
    if user is None:
        # Hash dummy para nivelar tempo
        verify_password(password, "$argon2id$v=19$m=65536,t=3,p=2$" + "A" * 22 + "$" + "A" * 43)
        raise AuthError("Credenciais inválidas")

    if user.locked_until and user.locked_until > now:
        raise AuthError("Conta temporariamente bloqueada")

    if not user.is_active:
        raise AuthError("Credenciais inválidas")

    if not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= MAX_FAILED:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
        await session.commit()
        raise AuthError("Credenciais inválidas")

    # Sucesso — reset contadores e (talvez) rehash silencioso
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    await session.commit()
    return user


def issue_token_pair(user: User) -> tuple[str, str, int]:
    """Emite (access, refresh, ttl_access_seconds)."""
    settings = get_settings()
    access, _, _ = issue_token(
        subject=str(user.id), role=user.role, token_type="access"
    )
    refresh, _, _ = issue_token(
        subject=str(user.id), role=user.role, token_type="refresh"
    )
    return access, refresh, settings.jwt_access_ttl_min * 60


async def refresh_tokens(
    session: AsyncSession, refresh_token: str
) -> tuple[str, str, int]:
    """Roda refresh com rotação: revoga o jti antigo e emite novo par."""
    try:
        payload = verify_token(refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise AuthError("Refresh inválido") from exc

    jti = payload["jti"]
    # Bloqueia replay: se já está revogado, falha
    revoked = await session.scalar(
        select(RevokedToken.jti).where(RevokedToken.jti == jti)
    )
    if revoked:
        raise AuthError("Refresh revogado")

    user_id = int(payload["sub"])
    user = await session.scalar(select(User).where(User.id == user_id))
    if not user or not user.is_active:
        raise AuthError("Usuário inválido")

    # Revoga o refresh antigo
    session.add(
        RevokedToken(
            jti=jti,
            typ="refresh",
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            actor_pseudonym=user.email_pseudonym,
        )
    )
    await session.commit()
    return issue_token_pair(user)


async def revoke_token(
    session: AsyncSession, *, jti: str, typ: str, exp_ts: int, actor: str
) -> None:
    session.add(
        RevokedToken(
            jti=jti,
            typ=typ,
            expires_at=datetime.fromtimestamp(exp_ts, tz=timezone.utc),
            actor_pseudonym=actor,
        )
    )
    await session.commit()


async def create_user(
    session: AsyncSession, *, email: str, password: str, role: UserRole
) -> User:
    """Cria usuário com pseudônimo HMAC do email + hash Argon2."""
    pseudonym = pseudonymize(email.lower())
    existing = await session.scalar(
        select(User).where(User.email_pseudonym == pseudonym)
    )
    if existing:
        raise AuthError("Já existe usuário com esse email")
    user = User(
        email_pseudonym=pseudonym,
        email_encrypted=email,  # cifrado pelo TypeDecorator
        password_hash=hash_password(password),
        role=role.value,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user
