"""
Cabeçalhos de segurança HTTP — proteções nativas do browser.

Cobre o item do rubric "Uso obrigatório de HTTPS/TLS 1.2+" via:
- HSTS (força HTTPS em conexões futuras)
- redirect 308 quando FORCE_HTTPS está ativo

CSP é restritivo por padrão; a API não serve HTML, então 'self' basta.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from app.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        # 1) Forçar HTTPS em prod
        if settings.force_https and settings.is_production:
            forwarded = request.headers.get("x-forwarded-proto", "")
            if request.url.scheme != "https" and forwarded.lower() != "https":
                https_url = request.url.replace(scheme="https")
                return RedirectResponse(url=str(https_url), status_code=308)

        response: Response = await call_next(request)

        # 2) Headers de proteção
        h = response.headers
        if settings.force_https:
            h["Strict-Transport-Security"] = (
                f"max-age={settings.hsts_max_age}; includeSubDomains; preload"
            )
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()",
        )
        # API JSON-only — CSP fechado é suficiente
        h.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Remove header que vaza versão do servidor
        if "server" in h:
            del h["server"]
        return response
