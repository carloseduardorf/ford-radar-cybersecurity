"""
Rate limiting baseado em janela fixa, totalmente in-process.

Por que não slowapi:
- O decorator do slowapi reescreve a assinatura da rota e quebra a
  resolução de Pydantic body params do FastAPI sob `from __future__ import
  annotations`.
- Manter a lógica como middleware ASGI dá controle total e zero acoplamento
  com o framework de rotas.

Estratégia:
- Janela fixa por chave (IP) e por bucket (rota).
- Buckets distintos: default (geral), auth (login/refresh), ingest (webhook).
- Storage em memória — para multi-instância usar Redis, mas a interface
  é a mesma.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import get_settings


def _parse_rate(spec: str) -> Tuple[int, int]:
    """'5/minute' -> (5, 60)"""
    n_str, unit = spec.split("/")
    n = int(n_str)
    seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}.get(unit.strip())
    if seconds is None:
        raise ValueError(f"Unidade de rate limit desconhecida: {unit}")
    return n, seconds


class _RateLimiter:
    """Limitador thread-safe in-memory."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

    def hit(self, *, bucket: str, key: str, limit: int, window: int) -> bool:
        """Retorna True se permitido, False se estourou."""
        now = time.time()
        cutoff = now - window
        with self._lock:
            dq = self._hits[(bucket, key)]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = _RateLimiter()


def _client_key(request: Request) -> str:
    """IP do cliente, respeitando X-Forwarded-For atrás de proxy interno."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _bucket_for(path: str) -> Tuple[str, str]:
    """Retorna (bucket_name, rate_spec)."""
    settings = get_settings()
    if path.startswith("/v1/auth/"):
        return "auth", settings.rate_limit_auth
    if path.startswith("/v1/ingest/"):
        return "ingest", settings.rate_limit_ingest
    return "default", settings.rate_limit_default


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Health checks ficam fora do rate limit (probes do orquestrador)
        if request.url.path in ("/healthz", "/readyz"):
            return await call_next(request)

        bucket, spec = _bucket_for(request.url.path)
        limit, window = _parse_rate(spec)
        key = _client_key(request)

        if not limiter.hit(bucket=bucket, key=key, limit=limit, window=window):
            # Importação tardia para evitar ciclo
            from app.audit.service import record_suspicious_event_sync_safe

            record_suspicious_event_sync_safe(
                kind="rate_limit_exceeded",
                severity="media",
                ip=key,
                detail=f"path={request.url.path} bucket={bucket}",
            )
            rid = getattr(request.state, "request_id", None)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Muitas requisições. Tente novamente em instantes.",
                    "request_id": rid,
                },
                headers={"Retry-After": str(window)},
            )

        return await call_next(request)
