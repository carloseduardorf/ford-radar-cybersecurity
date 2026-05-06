"""Base declarative + tipo decorador de criptografia em repouso."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, LargeBinary, TypeDecorator, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.security.crypto import CryptoError, decrypt_str, encrypt_str


class Base(DeclarativeBase):
    """Base declarative com timestamps automáticos."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class EncryptedStr(TypeDecorator):
    """Coluna que cifra automaticamente strings em AES-GCM.

    No DB grava bytes (token base64-url). Na aplicação, é str transparente.
    Use ``length`` para reservar espaço; o ciphertext cresce ~33% pelo
    base64 + 12 bytes de nonce + 16 de tag.
    """

    impl = LargeBinary
    cache_ok = True

    def process_bind_param(
        self, value: Optional[str], dialect
    ) -> Optional[bytes]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("EncryptedStr aceita apenas str")
        return encrypt_str(value).encode("ascii")

    def process_result_value(
        self, value: Optional[bytes], dialect
    ) -> Optional[str]:
        if value is None:
            return None
        try:
            return decrypt_str(value.decode("ascii"))
        except CryptoError:
            # Falha de decifragem em prod NÃO deve mascarar — o caller
            # precisa saber. Vazamos só "valor adulterado", sem detalhes.
            raise CryptoError("Coluna criptografada adulterada ou chave incorreta")
