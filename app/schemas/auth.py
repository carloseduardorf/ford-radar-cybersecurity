"""Schemas de autenticação."""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator

# Política mínima de senha: 12+ chars, ao menos 1 minúscula, 1 maiúscula,
# 1 dígito, 1 símbolo. Nada de "abcdefg12345" passando.
PASSWORD_POLICY_RE = re.compile(
    r"""
    ^(?=.*[a-z])     # 1 minúscula
     (?=.*[A-Z])     # 1 maiúscula
     (?=.*\d)        # 1 dígito
     (?=.*[^\w\s])   # 1 símbolo
     [\S]{12,128}$    # 12-128 chars não-espaço
    """,
    re.VERBOSE,
)


class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(..., max_length=254)
    password: SecretStr = Field(..., min_length=12, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=20, max_length=2048)


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(..., max_length=254)
    password: SecretStr = Field(..., min_length=12, max_length=128)
    role: str = Field(..., max_length=16)

    @field_validator("password")
    @classmethod
    def _check_password_strength(cls, v: SecretStr) -> SecretStr:
        if not PASSWORD_POLICY_RE.match(v.get_secret_value()):
            raise ValueError(
                "Senha precisa ter 12-128 chars com minúscula, maiúscula, "
                "dígito e símbolo, sem espaços."
            )
        return v

    @field_validator("role")
    @classmethod
    def _check_role(cls, v: str) -> str:
        if v not in {"admin", "analyst", "user"}:
            raise ValueError("Role inválida")
        return v
