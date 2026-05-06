"""
Emissão e verificação de JWTs com TTL curto + refresh token rotacionável.

Decisões de segurança:
- Algoritmo HS256 fixo (lista branca em config); rejeita "alg=none".
- Claims iss/aud/exp/iat/nbf obrigatórios + jti único.
- Tipo (access | refresh) embutido no claim 'typ' — verificado em runtime.
- TTLs curtos: access 15 min, refresh 7 dias com rotação.
"""
from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Literal

from jose import JWTError, jwt

from app.config import get_settings


class TokenError(Exception):
    """Falha de emissão/verificação. Mensagem segura para externalizar."""


TokenType = Literal["access", "refresh"]


def _now() -> int:
    return int(time.time())


def issue_token(
    *,
    subject: str,
    role: str,
    token_type: TokenType,
    extra_claims: Dict[str, Any] | None = None,
) -> tuple[str, str, int]:
    """Emite um JWT.

    Retorna (token, jti, exp_unix).
    """
    settings = get_settings()
    now = _now()
    if token_type == "access":
        ttl = settings.jwt_access_ttl_min * 60
    elif token_type == "refresh":
        ttl = settings.jwt_refresh_ttl_days * 86400
    else:  # pragma: no cover — defensive
        raise TokenError("Tipo de token inválido")

    jti = secrets.token_urlsafe(16)
    exp = now + ttl
    payload: Dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": subject,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": jti,
        "typ": token_type,
        "role": role,
    }
    if extra_claims:
        # Não permitir override dos claims críticos
        for k in ("iss", "aud", "sub", "iat", "exp", "jti", "typ", "nbf"):
            extra_claims.pop(k, None)
        payload.update(extra_claims)

    token = jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return token, jti, exp


def verify_token(token: str, *, expected_type: TokenType) -> Dict[str, Any]:
    """Decodifica e valida um JWT, retornando o payload.

    Levanta TokenError em qualquer falha (sem detalhes que ajudem o atacante).
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],  # lista fixa — bloqueia alg-confusion
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require_iat": True,
                "require_exp": True,
                "require_nbf": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except JWTError as exc:
        raise TokenError("Token inválido") from exc

    if payload.get("typ") != expected_type:
        raise TokenError("Tipo de token incorreto")
    if "sub" not in payload or "role" not in payload or "jti" not in payload:
        raise TokenError("Claims obrigatórios ausentes")
    return payload
