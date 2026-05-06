"""
Rubric 1 — Segurança de Entrada e Validação de Dados (20 pts)

✓ Sanitização contra SQL Injection / XSS / command injection
✓ Normalização e validação de parâmetros de API (marca, modelo, versão)
✓ Limitação de tamanho/formato (payload flooding, buffer overflow)
✓ Tratamento seguro de erros (sem stack trace, sem estrutura interna)
"""
import pytest
from pydantic import ValidationError

from app.schemas.competitor import CompetitorIn, CompetitorListQuery
from app.schemas.spreadsheet import SpreadsheetIngestRequest


@pytest.mark.parametrize(
    "name,payload",
    [
        ("XSS_basic", "<script>alert(1)</script>"),
        ("XSS_event", "\" onerror=alert(1) "),
        ("SQLi_or", "'; DROP TABLE users; --"),
        ("SQLi_union", "1' UNION SELECT password FROM users--"),
        ("cmd_inj_semicolon", "VW; rm -rf /"),
        ("cmd_inj_pipe", "VW && cat /etc/passwd"),
        ("cmd_inj_subst", "VW$(whoami)"),
        ("cmd_inj_backtick", "VW`id`"),
        ("path_traversal", "../../etc/passwd"),
        ("null_byte", "VW\x00admin"),
        ("rtl_override", "VW‮Amarok"),
        ("zero_width", "VW‍Amarok"),
        ("empty", ""),
        ("only_space", "   "),
    ],
)
def test_brand_rejects_attack(name, payload):
    """Marca/modelo/versão rejeitam padrões clássicos de injeção."""
    with pytest.raises(ValidationError):
        CompetitorIn(
            brand=payload,
            model="X",
            version="V",
            year=2024,
            horsepower=100,
            price_brl=1.0,
        )


def test_valid_competitor_passes():
    ok = CompetitorIn(
        brand="Volkswagen",
        model="Amarok",
        version="V6 Highline 3.0",
        year=2025,
        horsepower=258,
        price_brl=295_000.0,
        fipe_code="005340-1",
    )
    assert ok.brand == "Volkswagen"


def test_unicode_accents_allowed():
    """Aceitar acentos legítimos (PT-BR)."""
    ok = CompetitorIn(
        brand="Citroën",
        model="C4 Lounge",
        version="Pure Tech",
        year=2024,
        horsepower=165,
        price_brl=120_000.0,
    )
    assert ok.brand == "Citroën"


def test_string_length_limited():
    """Strings respeitam limite (anti buffer overflow conceitual)."""
    with pytest.raises(ValidationError):
        CompetitorIn(
            brand="V" * 200,
            model="X",
            version="V",
            year=2024,
            horsepower=100,
            price_brl=1.0,
        )


def test_numeric_bounds_enforced():
    with pytest.raises(ValidationError):
        CompetitorIn(
            brand="VW",
            model="X",
            version="V",
            year=1800,  # < 1990
            horsepower=100,
            price_brl=1.0,
        )
    with pytest.raises(ValidationError):
        CompetitorIn(
            brand="VW",
            model="X",
            version="V",
            year=2024,
            horsepower=999_999,  # > 2000
            price_brl=1.0,
        )
    with pytest.raises(ValidationError):
        CompetitorIn(
            brand="VW",
            model="X",
            version="V",
            year=2024,
            horsepower=100,
            price_brl=-1.0,  # negativo
        )


def test_extra_fields_rejected():
    """extra='forbid' impede mass assignment de claims privilegiados."""
    with pytest.raises(ValidationError):
        CompetitorIn(
            brand="VW",
            model="X",
            version="V",
            year=2024,
            horsepower=100,
            price_brl=1.0,
            is_admin=True,  # tentativa de mass assignment
        )


def test_pagination_bounds():
    """page_size limitado a 100 — impede tentativa de DoS via page_size enorme."""
    with pytest.raises(ValidationError):
        CompetitorListQuery(page=1, page_size=10_000)


def test_spreadsheet_size_bound():
    """Limite de 5000 linhas por planilha — anti payload flooding."""
    rows = [
        {
            "brand": "VW",
            "model": "X",
            "version": "V",
            "year": 2024,
            "horsepower": 100,
            "price_brl": 1.0,
        }
    ] * 6000
    with pytest.raises(ValidationError):
        SpreadsheetIngestRequest(
            filename="test.xlsx", sha256="a" * 64, rows=rows
        )


def test_spreadsheet_sha_format():
    with pytest.raises(ValidationError):
        SpreadsheetIngestRequest(
            filename="test.xlsx",
            sha256="not-a-valid-sha",
            rows=[
                {
                    "brand": "VW",
                    "model": "X",
                    "version": "V",
                    "year": 2024,
                    "horsepower": 100,
                    "price_brl": 1.0,
                }
            ],
        )


@pytest.mark.asyncio
async def test_validation_error_does_not_leak_input(client):
    """Erros de validação NÃO devem ecoar o input malicioso na resposta."""
    payload = {"email": "<script>x</script>", "password": "short"}
    r = await client.post("/v1/auth/login", json=payload)
    assert r.status_code == 422
    body = r.text
    # Não vazar payload original do atacante
    assert "<script>x</script>" not in body
    assert "request_id" in r.json()


@pytest.mark.asyncio
async def test_500_does_not_leak_stack_trace(client):
    """Endpoint inexistente não vaza stack."""
    r = await client.get("/this-route-does-not-exist")
    assert r.status_code == 404
    body = r.text
    assert "Traceback" not in body
    assert "/c/" not in body and "site-packages" not in body


@pytest.mark.asyncio
async def test_payload_size_limit(client, admin_token):
    """Body acima do limite global (~2 MiB) → 413."""
    # 3 MiB de string em campo legítimo
    big = "A" * (3 * 1024 * 1024)
    r = await client.post(
        "/v1/auth/login",
        json={"email": f"{big}@x.com", "password": "AdminPass!2026FordX"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code in (400, 413, 422)  # 413 ideal, 400/422 toleráveis


@pytest.mark.asyncio
async def test_content_length_announced_overlimit_rejected(client):
    """Content-Length declarado acima do limite é rejeitado imediatamente."""
    headers = {
        "Content-Length": str(50 * 1024 * 1024),
        "Content-Type": "application/json",
    }
    r = await client.post(
        "/v1/auth/login",
        content=b'{"email":"x@x.com","password":"AdminPass!2026FordX"}',
        headers=headers,
    )
    assert r.status_code == 413
