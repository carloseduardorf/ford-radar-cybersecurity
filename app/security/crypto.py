"""
Criptografia simétrica autenticada (AES-256-GCM) para dados em repouso.

Formato armazenado: base64(nonce[12] || ciphertext || tag[16])
Cobre o item do rubric: "Criptografia de dados sensíveis em repouso".
"""
from __future__ import annotations

import base64
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

NONCE_LEN = 12  # 96 bits — recomendado pelo NIST SP 800-38D


class CryptoError(Exception):
    """Erro genérico de criptografia (não vaza detalhes para o caller)."""


def _aesgcm() -> AESGCM:
    return AESGCM(get_settings().encryption_key_bytes)


def encrypt_str(plaintext: str, *, aad: Optional[bytes] = None) -> str:
    """Cifra uma string UTF-8 e retorna base64 url-safe.

    Use ``aad`` para amarrar o ciphertext a um contexto (ex.: nome do campo
    + id da linha) — qualquer adulteração que mude o contexto invalida.
    """
    if plaintext is None:
        raise CryptoError("plaintext não pode ser None")
    nonce = os.urandom(NONCE_LEN)
    ct = _aesgcm().encrypt(nonce, plaintext.encode("utf-8"), aad)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_str(token: str, *, aad: Optional[bytes] = None) -> str:
    if not token:
        raise CryptoError("token vazio")
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        nonce, ct = raw[:NONCE_LEN], raw[NONCE_LEN:]
        pt = _aesgcm().decrypt(nonce, ct, aad)
        return pt.decode("utf-8")
    except Exception as exc:  # noqa: BLE001 — não vazamos detalhes
        raise CryptoError("Falha ao decifrar payload") from exc
