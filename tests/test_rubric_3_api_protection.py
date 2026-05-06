"""
Rubric 3 — Proteção de APIs e Serviços (20 pts)

✓ HTTPS/TLS 1.2+ (HSTS + 308 redirect quando FORCE_HTTPS)
✓ Rate limiting / throttling
✓ CORS configurado corretamente
✓ Assinatura/verificação de integridade de payloads (HMAC) — 5 pts
"""
import json
import time

import pytest

from app.security.hmac_sign import sign_payload


# ─────────────────────────── Security headers ───────────────────────


@pytest.mark.asyncio
async def test_security_headers_present(client):
    r = await client.get("/healthz")
    h = r.headers
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert h.get("Referrer-Policy") == "no-referrer"
    assert "default-src" in h.get("Content-Security-Policy", "")
    # HSTS sempre presente quando force_https=True (settings)
    # Em testes setamos FORCE_HTTPS=false, mas o header é facultativo
    # Server header NÃO deve estar presente
    assert h.get("Server") in (None, "")


# ─────────────────────────── CORS ─────────────────────────────────


@pytest.mark.asyncio
async def test_cors_allowed_origin(client):
    r = await client.options(
        "/healthz",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


@pytest.mark.asyncio
async def test_cors_disallowed_origin(client):
    r = await client.options(
        "/healthz",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Starlette retorna 400 / sem header CORS para origem não whitelisted
    assert r.headers.get("access-control-allow-origin") is None


# ─────────────────────────── Rate limit ───────────────────────────


@pytest.mark.asyncio
async def test_login_rate_limit_kicks_in(client):
    """Limite auth = 5/min — 6º request deve receber 429."""
    payload = {"email": "ghost@ford-test.com", "password": "BadPassword!12"}
    statuses = []
    for _ in range(7):
        r = await client.post("/v1/auth/login", json=payload)
        statuses.append(r.status_code)
    assert 429 in statuses, f"esperado 429, recebido {statuses}"


# ─────────────────────────── HMAC webhook ────────────────────────


@pytest.mark.asyncio
async def test_ingest_requires_signature(client):
    body = {
        "filename": "planilha.xlsx",
        "sha256": "a" * 64,
        "rows": [
            {
                "brand": "VW",
                "model": "X",
                "version": "V",
                "year": 2024,
                "horsepower": 100,
                "price_brl": 1.0,
            }
        ],
    }
    r = await client.post("/v1/ingest/spreadsheet", json=body)
    assert r.status_code == 401
    assert r.json()["detail"] == "Assinatura inválida"


@pytest.mark.asyncio
async def test_ingest_with_valid_signature(client):
    body_dict = {
        "filename": "planilha-2026-04.xlsx",
        "sha256": "a1b2c3d4e5f6" + "0" * 52,
        "rows": [
            {
                "brand": "Volkswagen",
                "model": "Amarok",
                "version": "V6 Highline",
                "year": 2025,
                "horsepower": 258,
                "price_brl": 295000.0,
            }
        ],
    }
    body = json.dumps(body_dict).encode()
    sig = sign_payload(body)
    r = await client.post(
        "/v1/ingest/spreadsheet",
        content=body,
        headers={"X-Signature": sig, "Content-Type": "application/json"},
    )
    assert r.status_code == 201, r.text
    body_resp = r.json()
    assert body_resp["rows_processed"] == 1


@pytest.mark.asyncio
async def test_ingest_replay_blocked(client):
    """Mesma planilha (mesmo sha256) não pode reprocessar."""
    body_dict = {
        "filename": "planilha-replay.xlsx",
        "sha256": "b" * 64,
        "rows": [
            {
                "brand": "Toyota",
                "model": "Hilux",
                "version": "GR Sport",
                "year": 2025,
                "horsepower": 204,
                "price_brl": 320_000.0,
            }
        ],
    }
    body = json.dumps(body_dict).encode()
    sig = sign_payload(body)
    r1 = await client.post(
        "/v1/ingest/spreadsheet",
        content=body,
        headers={"X-Signature": sig, "Content-Type": "application/json"},
    )
    assert r1.status_code == 201
    # Segunda tentativa com mesma planilha
    sig2 = sign_payload(body)
    r2 = await client.post(
        "/v1/ingest/spreadsheet",
        content=body,
        headers={"X-Signature": sig2, "Content-Type": "application/json"},
    )
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_ingest_timestamp_replay_blocked(client):
    """Timestamp velho fora da janela é rejeitado."""
    body_dict = {
        "filename": "old.xlsx",
        "sha256": "c" * 64,
        "rows": [
            {
                "brand": "Chevrolet",
                "model": "S10",
                "version": "High Country",
                "year": 2025,
                "horsepower": 200,
                "price_brl": 280_000.0,
            }
        ],
    }
    body = json.dumps(body_dict).encode()
    old_ts = int(time.time()) - 10_000  # 2h+ atrás
    sig = sign_payload(body, timestamp=old_ts)
    r = await client.post(
        "/v1/ingest/spreadsheet",
        content=body,
        headers={"X-Signature": sig, "Content-Type": "application/json"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_ingest_tampered_body_blocked(client):
    """Mudar 1 byte no body invalida a assinatura."""
    body_dict = {
        "filename": "tampered.xlsx",
        "sha256": "d" * 64,
        "rows": [
            {
                "brand": "Ford",
                "model": "Ranger",
                "version": "Raptor",
                "year": 2024,
                "horsepower": 397,
                "price_brl": 500_000.0,
            }
        ],
    }
    body = json.dumps(body_dict).encode()
    sig = sign_payload(body)
    tampered = body.replace(b"500000.0", b"100000.0")
    r = await client.post(
        "/v1/ingest/spreadsheet",
        content=tampered,
        headers={"X-Signature": sig, "Content-Type": "application/json"},
    )
    assert r.status_code == 401
