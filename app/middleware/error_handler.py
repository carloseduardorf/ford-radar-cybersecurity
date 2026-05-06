"""
Handler de erros uniforme.

Em produção:
- Exceções não-tratadas viram 500 com detail genérico + request_id.
- Erros de validação Pydantic não retornam o `input` original (que pode
  conter payload malicioso que o atacante quer ver ecoado).
- Stack trace NUNCA vai para o cliente; vai para o log estruturado.
"""
from __future__ import annotations

from typing import Any, Dict, List

import structlog
from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.config import get_settings
from app.security.crypto import CryptoError
from app.security.hmac_sign import SignatureError
from app.security.jwt import TokenError

logger = structlog.get_logger("app.errors")


def _sanitize_validation_errors(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove o campo 'input' (pode conter o payload malicioso)."""
    cleaned = []
    for err in errors:
        cleaned.append(
            {
                "loc": err.get("loc"),
                "msg": err.get("msg"),
                "type": err.get("type"),
            }
        )
    return cleaned


async def _generic_500(request: Request, detail: str = "Erro interno") -> JSONResponse:
    rid = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": detail, "request_id": rid},
    )


def register_error_handlers(app) -> None:
    settings = get_settings()

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        rid = getattr(request.state, "request_id", None)
        # Log COMPLETO do lado do servidor (com input)
        logger.warning(
            "request.validation_error",
            request_id=rid,
            path=request.url.path,
            errors=exc.errors(),
        )
        # Resposta SAFE para o cliente (sem input)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Dados de entrada inválidos",
                "errors": _sanitize_validation_errors(exc.errors()),
                "request_id": rid,
            },
        )

    @app.exception_handler(HTTPException)
    async def _http_handler(request: Request, exc: HTTPException):
        rid = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "request_id": rid},
            headers=exc.headers or {},
        )

    @app.exception_handler(TokenError)
    async def _token_handler(request: Request, exc: TokenError):
        rid = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Autenticação falhou", "request_id": rid},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(SignatureError)
    async def _sig_handler(request: Request, exc: SignatureError):
        rid = getattr(request.state, "request_id", None)
        logger.warning(
            "webhook.signature_invalid",
            request_id=rid,
            path=request.url.path,
            reason=str(exc),
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Assinatura inválida", "request_id": rid},
        )

    @app.exception_handler(CryptoError)
    async def _crypto_handler(request: Request, exc: CryptoError):
        rid = getattr(request.state, "request_id", None)
        logger.error("crypto.failure", request_id=rid, exc_info=True)
        return await _generic_500(request, detail="Erro ao processar dados protegidos")

    @app.exception_handler(SQLAlchemyError)
    async def _sa_handler(request: Request, exc: SQLAlchemyError):
        rid = getattr(request.state, "request_id", None)
        # Log com detalhes — mas resposta genérica
        logger.error(
            "db.error",
            request_id=rid,
            path=request.url.path,
            exc_info=True,
        )
        return await _generic_500(request, detail="Erro no banco de dados")

    @app.exception_handler(Exception)
    async def _fallback_handler(request: Request, exc: Exception):
        rid = getattr(request.state, "request_id", None)
        logger.error(
            "unhandled.exception",
            request_id=rid,
            path=request.url.path,
            exc_info=True,
        )
        # Em DEV podemos incluir o tipo da exceção pra facilitar debug
        if not settings.is_production:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": "Erro interno",
                    "type": exc.__class__.__name__,
                    "request_id": rid,
                },
            )
        return await _generic_500(request)
