"""
Logging estruturado JSON com redação automática de campos sensíveis.

Por que JSON:
- Trilha estruturada → ingestão direta em SIEM (Splunk, ELK, Datadog).
- Nunca incluir PII (email, senha, token) em log; redator centralizado
  garante isso mesmo se um dev esquecer.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Any, Dict

import structlog

REDACT = "***REDACTED***"

# Padrões que identificam dados sensíveis em qualquer profundidade
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token",
    "refresh_token", "authorization", "cookie", "set-cookie",
    "email", "x-signature", "x-api-key", "api_key",
}

EMAIL_RE = re.compile(r"\b[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def _redact_value(v: Any) -> Any:
    if isinstance(v, str):
        v = EMAIL_RE.sub(REDACT, v)
        v = JWT_RE.sub(REDACT, v)
    return v


def _redact_event(_, __, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Processor structlog: redige chaves sensíveis recursivamente."""

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: (REDACT if k.lower() in SENSITIVE_KEYS else walk(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [walk(x) for x in value]
        return _redact_value(value)

    return walk(event_dict)


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level.upper(),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact_event,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
