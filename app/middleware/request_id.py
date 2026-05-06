"""Atribui um UUID único por request — correlação log/audit/error."""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        # Aceita request-id externo só se for UUID válido (não confiar no cliente)
        try:
            uuid.UUID(rid)
        except ValueError:
            rid = str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response
