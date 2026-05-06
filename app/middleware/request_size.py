"""
Limite de tamanho de payload — defesa contra payload flooding / DoS.

Funciona em duas camadas:
1) Inspeciona Content-Length (rejeição imediata).
2) Conta bytes lidos do stream (caso o atacante mande sem Content-Length).
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import get_settings


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Aplica limites diferenciados por rota.

    Rotas de upload (multipart) usam max_upload_bytes; demais, max_request_bytes.
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        # Determina limite baseado em path/content-type
        path = request.url.path
        is_upload = path.startswith("/v1/spreadsheets") and request.method == "POST"
        limit = settings.max_upload_bytes if is_upload else settings.max_request_bytes

        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > limit:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Payload acima do limite permitido"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Content-Length inválido"},
                )

        # Wrap do receive para contar bytes em streaming
        body_size = 0
        original_receive = request._receive

        async def counting_receive():
            nonlocal body_size
            message = await original_receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"") or b""
                body_size += len(chunk)
                if body_size > limit:
                    # Cancela: retornará erro pela exceção
                    raise PayloadTooLarge()
            return message

        request._receive = counting_receive

        try:
            return await call_next(request)
        except PayloadTooLarge:
            return JSONResponse(
                status_code=413,
                content={"detail": "Payload acima do limite permitido"},
            )


class PayloadTooLarge(Exception):
    pass
