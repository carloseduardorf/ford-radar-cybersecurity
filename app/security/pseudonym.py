"""
Pseudonimização determinística via HMAC-SHA256.

Caso de uso: anonimizar identificadores de usuário ao alimentar modelos
de ML ou ao compor logs/dashboards de analistas que não devem ver PII.

Determinístico: o mesmo input mapeia para o mesmo pseudônimo
(permite joins) — mas o atacante sem o salt não consegue reverter.

Diferença para anonimização:
- pseudonimização: reversível com a chave (salt + HMAC inverso impossível,
  mas via lookup table mantida pelo controlador).
- anonimização: irreversível, sem chance de identificar (mesmo com chave).
"""
from __future__ import annotations

import hashlib
import hmac

from app.config import get_settings


def pseudonymize(identifier: str) -> str:
    """Retorna pseudônimo hex de 16 bytes (32 chars) para o identificador."""
    if not identifier:
        raise ValueError("identifier vazio")
    salt = get_settings().pseudonym_salt.get_secret_value().encode("utf-8")
    digest = hmac.new(salt, identifier.encode("utf-8"), hashlib.sha256).digest()
    # 16 bytes hex — colisão astronomicamente improvável para o volume
    # esperado (analistas + concorrentes).
    return digest[:16].hex()


def anonymize_email(email: str) -> str:
    """Anonimiza um email para logs: a***@dominio.com."""
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"
