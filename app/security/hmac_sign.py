"""
Assinatura/verificação HMAC-SHA256 para integridade de payloads em trânsito.

Caso de uso central no challenge: o n8n dispara o webhook /ingest quando
uma planilha nova chega. Sem HMAC, qualquer um que descobrir a URL pode
injetar dados falsos no pipeline de ML.

Formato do header X-Signature:
    "t=<unix_seconds>,v1=<hex_hmac_sha256>"

A assinatura cobre f"{t}.{body}" — concatenar o timestamp impede replays.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Tuple

from app.config import get_settings


class SignatureError(Exception):
    """Falha de validação de assinatura (mensagem segura)."""


def _hmac_hex(secret: bytes, msg: bytes) -> str:
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def sign_payload(body: bytes, *, timestamp: int | None = None) -> str:
    """Gera o valor do header X-Signature para um corpo de requisição."""
    settings = get_settings()
    secret = settings.webhook_hmac_secret.get_secret_value().encode("utf-8")
    t = int(timestamp if timestamp is not None else time.time())
    msg = f"{t}.".encode("ascii") + body
    return f"t={t},v1={_hmac_hex(secret, msg)}"


def _parse_header(header: str) -> Tuple[int, str]:
    parts = {}
    for pair in header.split(","):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        parts[k.strip()] = v.strip()
    if "t" not in parts or "v1" not in parts:
        raise SignatureError("Cabeçalho de assinatura malformado")
    try:
        t = int(parts["t"])
    except ValueError as exc:
        raise SignatureError("Timestamp inválido") from exc
    return t, parts["v1"]


def verify_signature(body: bytes, header: str | None) -> None:
    """Verifica X-Signature. Levanta SignatureError em qualquer falha.

    Defesas:
    - compare_digest: timing attack
    - tolerância de timestamp: replay attack
    """
    if not header:
        raise SignatureError("Assinatura ausente")
    settings = get_settings()
    t, sig_provided = _parse_header(header)

    skew = abs(int(time.time()) - t)
    if skew > settings.webhook_timestamp_tolerance_sec:
        raise SignatureError("Timestamp fora da janela de tolerância")

    secret = settings.webhook_hmac_secret.get_secret_value().encode("utf-8")
    msg = f"{t}.".encode("ascii") + body
    sig_expected = _hmac_hex(secret, msg)

    if not hmac.compare_digest(sig_expected, sig_provided):
        raise SignatureError("Assinatura inválida")
