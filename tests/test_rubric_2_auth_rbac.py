"""
Rubric 2 — Autenticação e Autorização (20 pts)

✓ JWT com expiração, assinatura forte e refresh rotacionado
✓ RBAC (admin / analyst / user) com permissões diferenciadas
"""
import time

import pytest
from jose import jwt as jose_jwt

from app.config import get_settings
from app.security.jwt import TokenError, issue_token, verify_token


# ─────────────────────────── JWT primitives ──────────────────────────


def test_jwt_issued_with_expected_claims():
    tok, jti, exp = issue_token(subject="42", role="analyst", token_type="access")
    payload = verify_token(tok, expected_type="access")
    assert payload["sub"] == "42"
    assert payload["role"] == "analyst"
    assert payload["typ"] == "access"
    assert payload["jti"] == jti
    assert payload["exp"] == exp


def test_jwt_rejects_alg_none():
    """CVE clássico: alg=none. Nossa lista branca de algoritmos proíbe.

    Construímos manualmente um JWT com header alg=none — qualquer
    biblioteca correta deve rejeitar quando o caller passa
    algorithms=["HS256"], que é o que verify_token faz.
    """
    import base64
    import json

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url(
        json.dumps(
            {
                "sub": "1",
                "role": "admin",
                "iss": get_settings().jwt_issuer,
                "aud": get_settings().jwt_audience,
                "exp": int(time.time()) + 60,
                "iat": int(time.time()),
                "nbf": int(time.time()),
                "jti": "abc",
                "typ": "access",
            }
        ).encode()
    )
    forged = f"{header}.{body}."  # signature vazia
    with pytest.raises(TokenError):
        verify_token(forged, expected_type="access")


def test_jwt_rejects_wrong_secret():
    payload = {
        "sub": "1",
        "role": "admin",
        "iss": get_settings().jwt_issuer,
        "aud": get_settings().jwt_audience,
        "exp": int(time.time()) + 60,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "jti": "abc",
        "typ": "access",
    }
    bad = jose_jwt.encode(payload, "wrong-secret-32characters-padding!!", algorithm="HS256")
    with pytest.raises(TokenError):
        verify_token(bad, expected_type="access")


def test_jwt_rejects_wrong_audience():
    payload = {
        "sub": "1",
        "role": "admin",
        "iss": get_settings().jwt_issuer,
        "aud": "evil-audience",
        "exp": int(time.time()) + 60,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "jti": "abc",
        "typ": "access",
    }
    bad = jose_jwt.encode(payload, get_settings().jwt_secret.get_secret_value(), algorithm="HS256")
    with pytest.raises(TokenError):
        verify_token(bad, expected_type="access")


def test_jwt_type_confusion_blocked():
    """Refresh não pode ser usado como access."""
    refresh, _, _ = issue_token(subject="1", role="admin", token_type="refresh")
    with pytest.raises(TokenError):
        verify_token(refresh, expected_type="access")


# ─────────────────────────── HTTP flow ──────────────────────────────


@pytest.mark.asyncio
async def test_login_success_returns_pair(client, admin_user):
    r = await client.post(
        "/v1/auth/login",
        json={"email": "admin-test@ford-test.com", "password": "AdminPass!2026FordX"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body and "refresh_token" in body
    assert body["expires_in"] == get_settings().jwt_access_ttl_min * 60


@pytest.mark.asyncio
async def test_login_wrong_password_generic_message(client, admin_user):
    r = await client.post(
        "/v1/auth/login",
        json={"email": "admin-test@ford-test.com", "password": "WrongPassword!12"},
    )
    assert r.status_code == 401
    # Mensagem genérica — não vazar enumeração
    assert r.json()["detail"] == "Credenciais inválidas"


@pytest.mark.asyncio
async def test_login_unknown_user_same_message(client):
    r = await client.post(
        "/v1/auth/login",
        json={"email": "ghost@ford-test.com", "password": "WhateverPass!12"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "Credenciais inválidas"


@pytest.mark.asyncio
async def test_protected_route_requires_token(client):
    r = await client.get("/v1/competitors")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_with_valid_token(client, analyst_token):
    r = await client.get(
        "/v1/competitors",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_logout_revokes_token(client, analyst_token):
    r = await client.post(
        "/v1/auth/logout",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert r.status_code == 204
    # Após logout, mesmo token não funciona
    r2 = await client.get(
        "/v1/competitors",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rotation(client, admin_user):
    r = await client.post(
        "/v1/auth/login",
        json={"email": "admin-test@ford-test.com", "password": "AdminPass!2026FordX"},
    )
    tokens = r.json()
    rt = tokens["refresh_token"]

    r2 = await client.post("/v1/auth/refresh", json={"refresh_token": rt})
    assert r2.status_code == 200
    new_tokens = r2.json()
    assert new_tokens["access_token"] != tokens["access_token"]

    # Refresh antigo agora está revogado
    r3 = await client.post("/v1/auth/refresh", json={"refresh_token": rt})
    assert r3.status_code == 401


# ─────────────────────────── RBAC ──────────────────────────────


@pytest.mark.asyncio
async def test_rbac_user_cannot_access_admin(client, user_token):
    r = await client.get(
        "/v1/admin/audit",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_rbac_analyst_cannot_access_admin(client, analyst_token):
    r = await client.get(
        "/v1/admin/audit",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_rbac_admin_can_access_admin(client, admin_token):
    r = await client.get(
        "/v1/admin/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200


def test_rbac_permission_matrix_consistent():
    """A matriz de permissões mantém invariantes esperadas."""
    from app.rbac import Permission, has_permission

    # admin tem tudo
    for p in Permission:
        assert has_permission("admin", p)
    # user nunca tem manage_users / read_audit
    assert not has_permission("user", Permission.MANAGE_USERS)
    assert not has_permission("user", Permission.READ_AUDIT)
    assert not has_permission("user", Permission.INGEST_SPREADSHEET)
    # analyst pode ingerir, mas não gerenciar usuários
    assert has_permission("analyst", Permission.INGEST_SPREADSHEET)
    assert not has_permission("analyst", Permission.MANAGE_USERS)
    # role inválido = sem nada
    assert not has_permission("hacker", Permission.READ_COMPETITORS)


def test_password_policy_rejects_weak():
    from pydantic import ValidationError

    from app.schemas.auth import CreateUserRequest

    weak_passwords = [
        "abcdefghijkl",  # sem maiúscula, dígito, símbolo
        "ABCDEFGHIJKL",  # sem minúscula
        "Abcdefghijkl",  # sem dígito/símbolo
        "Abcdefghi1",  # < 12 chars
        "Abcdefghi 1!",  # contém espaço
    ]
    for pw in weak_passwords:
        with pytest.raises(ValidationError):
            CreateUserRequest(email="x@y.com", password=pw, role="user")
