"""
Hashing de senhas usando Argon2id (vencedor do PHC).

Por que Argon2id e não bcrypt:
- Memory-hard: caro em GPU/ASIC.
- 'id' = híbrido data-dependent + data-independent (resistente a both
  side-channel e tradeoff attacks).
"""
from __future__ import annotations

from passlib.context import CryptContext

# time_cost / memory_cost / parallelism são dimensionados para alvo
# ~250 ms por hash em hardware moderno. Ajustar via benchmark em prod.
_pwd_ctx = CryptContext(
    schemes=["argon2"],
    argon2__time_cost=3,
    argon2__memory_cost=64 * 1024,  # 64 MiB
    argon2__parallelism=2,
    deprecated="auto",
)


def hash_password(password: str) -> str:
    if not password or len(password) < 12:
        # Política mínima: 12 chars. Camada superior valida força.
        raise ValueError("Senha deve ter pelo menos 12 caracteres")
    return _pwd_ctx.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _pwd_ctx.verify(password, hashed)
    except Exception:
        # Nunca vazar detalhes do erro de hash
        return False


def needs_rehash(hashed: str) -> bool:
    """True se o parâmetro de custo está abaixo do alvo atual.

    Permite rehashar o cofre transparentemente no próximo login bem
    sucedido — *upgrade silencioso*.
    """
    return _pwd_ctx.needs_update(hashed)
