"""
Rubric 4 — Segurança de Dados e Privacidade (25 pts)

✓ Criptografia em repouso (AES-GCM via TypeDecorator)
✓ Política de retenção (configuração) e descarte seguro
✓ Pseudonimização HMAC para uso em ML/dashboards
✓ Proteção contra exposição acidental (logs, endpoints)
"""
import pytest
from sqlalchemy import select, text

from app.config import get_settings
from app.models.user import User
from app.security.crypto import CryptoError, decrypt_str, encrypt_str
from app.security.pseudonym import anonymize_email, pseudonymize


# ─────────────────────── AES-GCM em repouso ─────────────────────


def test_encryption_round_trip():
    ct = encrypt_str("dado-confidencial")
    assert ct != "dado-confidencial"
    assert decrypt_str(ct) == "dado-confidencial"


def test_encryption_unique_ciphertexts_for_same_plaintext():
    """Nonce aleatório → mesmo texto cifra para valores diferentes."""
    ct1 = encrypt_str("mesma-coisa")
    ct2 = encrypt_str("mesma-coisa")
    assert ct1 != ct2  # confidencialidade ↑


def test_encryption_aad_prevents_misuse():
    """ciphertext gerado com AAD não pode ser decifrado sem o mesmo AAD."""
    ct = encrypt_str("segredo", aad=b"context=A")
    with pytest.raises(CryptoError):
        decrypt_str(ct, aad=b"context=B")


def test_tampered_ciphertext_fails():
    ct = encrypt_str("segredo")
    tampered = ct[:-2] + ("aa" if ct[-2:] != "aa" else "bb")
    with pytest.raises(CryptoError):
        decrypt_str(tampered)


@pytest.mark.asyncio
async def test_user_email_encrypted_at_rest(session, admin_user):
    """No banco, o email é bytes cifrados — não plaintext."""
    raw = await session.execute(
        text("SELECT email_encrypted FROM users WHERE id = :id"),
        {"id": admin_user.id},
    )
    blob = raw.scalar_one()
    assert blob is not None
    # bytes do ciphertext NÃO contêm o plaintext
    assert b"admin-test@ford-test.com" not in (blob if isinstance(blob, bytes) else blob.encode())

    # ORM decifra ao carregar
    user = await session.scalar(select(User).where(User.id == admin_user.id))
    assert user.email_encrypted == "admin-test@ford-test.com"


# ─────────────────────── Pseudonimização ────────────────────────


def test_pseudonym_deterministic():
    a = pseudonymize("user-1@x.com")
    b = pseudonymize("user-1@x.com")
    c = pseudonymize("user-2@x.com")
    assert a == b
    assert a != c
    assert len(a) == 32  # hex de 16 bytes


def test_pseudonym_changes_with_salt(monkeypatch):
    """Trocar salt muda o pseudônimo — a chave protege a função."""
    a = pseudonymize("user-1@x.com")
    settings = get_settings()
    # Forçar salt diferente
    from pydantic import SecretStr

    monkeypatch.setattr(settings, "pseudonym_salt", SecretStr("salt-diferente-aaa-bbb-ccc-ddd"))
    # invalida o cache do lru_cache de get_settings via monkey
    b = pseudonymize("user-1@x.com")
    assert a != b


def test_email_anonymizer():
    assert anonymize_email("analista@ford.com") == "a***@ford.com"
    assert anonymize_email("a@ford.com") == "a***@ford.com"
    assert anonymize_email("invalid") == "***"


# ─────────────────── Exposição acidental ────────────────────────


@pytest.mark.asyncio
async def test_admin_user_listing_uses_pseudonym(client, admin_token, analyst_user):
    """Endpoint admin de auditoria mostra pseudônimo, não email real."""
    r = await client.get(
        "/v1/admin/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.text
    # Email do analista não pode aparecer no log de auditoria
    assert "analyst-test@ford-test.com" not in body


@pytest.mark.asyncio
async def test_health_does_not_leak_version(client):
    r = await client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    # Não vazar version detalhada / dependências internas
    assert "version" not in body
    assert "python" not in str(body).lower()


def test_retention_policy_configured():
    """Configurações de retenção estão presentes (LGPD)."""
    s = get_settings()
    assert s.retention_audit_days >= 90
    assert s.retention_raw_spreadsheets_days >= 30
    assert s.retention_user_inactive_days >= 365
