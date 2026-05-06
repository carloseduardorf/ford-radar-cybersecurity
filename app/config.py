"""
Configuração central via Pydantic Settings.

Princípio: fail-closed. Se um segredo crítico não estiver presente em
produção, a aplicação se recusa a subir. Vale mais um deploy quebrado
do que um serviço aberto.
"""
from __future__ import annotations

import base64
import secrets
from enum import Enum
from functools import lru_cache
from typing import List

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(str, Enum):
    development = "development"
    staging = "staging"
    production = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Identidade ───────────────────────────────────────────────────
    app_env: AppEnv = AppEnv.development
    app_name: str = "Ford Radar Competitivo"
    app_version: str = "1.0.0"
    app_host: str = "0.0.0.0"
    app_port: int = 8000

    # ─── Banco ────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./challenge.db"

    # ─── Cripto / pseudonimização ─────────────────────────────────────
    encryption_key: SecretStr = SecretStr("")
    pseudonym_salt: SecretStr = SecretStr("")

    # ─── JWT ──────────────────────────────────────────────────────────
    jwt_secret: SecretStr = SecretStr("")
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_min: int = 15
    jwt_refresh_ttl_days: int = 7
    jwt_issuer: str = "ford-radar"
    jwt_audience: str = "ford-radar-clients"

    # ─── HMAC webhook ─────────────────────────────────────────────────
    webhook_hmac_secret: SecretStr = SecretStr("")
    webhook_timestamp_tolerance_sec: int = 300

    # ─── CORS ─────────────────────────────────────────────────────────
    cors_allowed_origins: str = ""

    # ─── Rate limit ───────────────────────────────────────────────────
    rate_limit_default: str = "100/minute"
    rate_limit_auth: str = "10/minute"
    rate_limit_ingest: str = "30/minute"

    # ─── Limites ──────────────────────────────────────────────────────
    max_request_bytes: int = 2 * 1024 * 1024
    max_upload_bytes: int = 20 * 1024 * 1024
    max_string_length: int = 512

    # ─── Retenção (LGPD) ──────────────────────────────────────────────
    retention_audit_days: int = 365
    retention_raw_spreadsheets_days: int = 180
    retention_user_inactive_days: int = 730

    # ─── HTTPS ────────────────────────────────────────────────────────
    force_https: bool = True
    hsts_max_age: int = 63_072_000

    # ─── Bootstrap admin ──────────────────────────────────────────────
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: SecretStr = SecretStr("")

    # ──────────────────────────────────────────────────────────────────
    # Validações de segurança
    # ──────────────────────────────────────────────────────────────────

    @field_validator("encryption_key")
    @classmethod
    def _validate_encryption_key(cls, v: SecretStr) -> SecretStr:
        # Permite vazio em dev (geramos efêmero); em prod o validador de
        # ambiente abaixo bloqueia.
        raw = v.get_secret_value()
        if not raw:
            return v
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise ValueError("ENCRYPTION_KEY deve ser base64 válido") from exc
        if len(decoded) != 32:
            raise ValueError("ENCRYPTION_KEY deve decodificar para 32 bytes (AES-256)")
        return v

    @field_validator("jwt_algorithm")
    @classmethod
    def _validate_jwt_alg(cls, v: str) -> str:
        # Lista branca: nunca aceitar "none" (CVE clássico)
        allowed = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
        if v not in allowed:
            raise ValueError(f"JWT_ALGORITHM precisa estar em {allowed}")
        return v

    @field_validator("rate_limit_default", "rate_limit_auth", "rate_limit_ingest")
    @classmethod
    def _validate_rate_limit(cls, v: str) -> str:
        # Formato slowapi: "<n>/<unit>"
        parts = v.split("/")
        if len(parts) != 2 or not parts[0].isdigit():
            raise ValueError(f"Rate limit inválido: {v!r} (esperado 'N/unit')")
        return v

    @model_validator(mode="after")
    def _enforce_production_security(self) -> "Settings":
        if self.app_env != AppEnv.production:
            # Em dev/staging, geramos segredos efêmeros se faltarem,
            # mas LOGAMOS aviso depois (logger ainda não disponível aqui).
            if not self.encryption_key.get_secret_value():
                self.encryption_key = SecretStr(
                    base64.b64encode(secrets.token_bytes(32)).decode()
                )
            if not self.pseudonym_salt.get_secret_value():
                self.pseudonym_salt = SecretStr(secrets.token_urlsafe(32))
            if not self.jwt_secret.get_secret_value():
                self.jwt_secret = SecretStr(secrets.token_urlsafe(64))
            if not self.webhook_hmac_secret.get_secret_value():
                self.webhook_hmac_secret = SecretStr(secrets.token_urlsafe(48))
            return self

        # ─── PRODUÇÃO: fail-closed ────────────────────────────────────
        problems: List[str] = []

        if not self.encryption_key.get_secret_value():
            problems.append("ENCRYPTION_KEY ausente")
        if not self.pseudonym_salt.get_secret_value() or len(
            self.pseudonym_salt.get_secret_value()
        ) < 32:
            problems.append("PSEUDONYM_SALT ausente ou < 32 chars")
        if not self.jwt_secret.get_secret_value() or len(
            self.jwt_secret.get_secret_value()
        ) < 32:
            problems.append("JWT_SECRET ausente ou < 32 chars")
        if not self.webhook_hmac_secret.get_secret_value() or len(
            self.webhook_hmac_secret.get_secret_value()
        ) < 32:
            problems.append("WEBHOOK_HMAC_SECRET ausente ou < 32 chars")
        if self.database_url.startswith("sqlite"):
            problems.append("SQLite não é permitido em produção")
        if not self.force_https:
            problems.append("FORCE_HTTPS deve estar ativo em produção")
        if "*" in self.cors_allowed_origins:
            problems.append("CORS wildcard '*' proibido em produção")
        if not self.cors_allowed_origins.strip():
            problems.append("CORS_ALLOWED_ORIGINS vazio")

        if problems:
            raise ValueError(
                "Configuração insegura para produção: " + "; ".join(problems)
            )
        return self

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @property
    def cors_origins_list(self) -> List[str]:
        return [
            o.strip()
            for o in self.cors_allowed_origins.split(",")
            if o.strip()
        ]

    @property
    def is_production(self) -> bool:
        return self.app_env == AppEnv.production

    @property
    def encryption_key_bytes(self) -> bytes:
        return base64.b64decode(self.encryption_key.get_secret_value())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
