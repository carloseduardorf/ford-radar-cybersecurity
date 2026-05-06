"""
Cria o usuário admin inicial a partir das vars BOOTSTRAP_ADMIN_*.

Idempotente: se já existe, não recria. Use em first-run ou em pipelines
de deploy. Após o primeiro admin, use POST /v1/admin/users.
"""
from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

from app.config import get_settings
from app.database import session_scope
from app.models.user import User, UserRole
from app.security.hashing import hash_password
from app.security.pseudonym import pseudonymize


async def main() -> int:
    s = get_settings()
    email = s.bootstrap_admin_email.strip().lower()
    pw = s.bootstrap_admin_password.get_secret_value()
    if not email or not pw:
        print("BOOTSTRAP_ADMIN_EMAIL/PASSWORD não definidos.", file=sys.stderr)
        return 2
    if len(pw) < 12:
        print("Senha bootstrap precisa ter ao menos 12 chars.", file=sys.stderr)
        return 2

    pseudonym = pseudonymize(email)
    async with session_scope() as session:
        existing = await session.scalar(
            select(User).where(User.email_pseudonym == pseudonym)
        )
        if existing:
            print(f"Admin já existe (pseudonym={pseudonym[:8]}...). Nada a fazer.")
            return 0
        u = User(
            email_pseudonym=pseudonym,
            email_encrypted=email,
            password_hash=hash_password(pw),
            role=UserRole.admin.value,
            is_active=True,
        )
        session.add(u)
    print(f"Admin criado (pseudonym={pseudonym[:8]}...).")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
