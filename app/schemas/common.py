"""
Validadores reutilizáveis e padrões de string seguros.

Princípio: aceitar apenas o conjunto positivo conhecido de caracteres
(allowlist), não tentar limpar caracteres perigosos (denylist sempre vaza).
"""
from __future__ import annotations

import re
import unicodedata
from typing import Annotated

from pydantic import BeforeValidator, Field, StringConstraints

# ─── Padrões ──────────────────────────────────────────────────────────
# Marca / modelo / versão: letras (incl. acentuadas), dígitos, espaço,
# hífen, ponto, underscore, barra. NÃO inclui ; ' " < > & ( ) { } | $
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9À-ÿ][A-Za-z0-9À-ÿ \-\._/]*$")

# Códigos numéricos/alfanuméricos compactos (FIPE, etc.)
SAFE_CODE_RE = re.compile(r"^[A-Za-z0-9\-]{1,32}$")


def _normalize_unicode(value: object) -> object:
    """Normaliza para NFC e REJEITA caracteres de controle.

    Defesa contra:
    - Homoglyph attacks (ɴ vs N, ҝ vs k).
    - Caracteres invisíveis (ZWJ, ZWNJ, BIDI override).
    - Null bytes (\\x00) usados em truncation attacks.

    Estratégia: falhar em vez de silenciosamente sanitizar — sanitização
    silenciosa pode levar payloads adulterados a serem persistidos.
    """
    if not isinstance(value, str):
        return value
    nfc = unicodedata.normalize("NFC", value)
    for ch in nfc:
        cat = unicodedata.category(ch)
        if cat[0] == "C" and ch not in {" "}:  # categorias C* = controle/format/sep
            raise ValueError("Caractere de controle ou invisível não permitido")
    return nfc.strip()


def _reject_dangerous(value: object) -> object:
    """Rejeita explicitamente padrões clássicos de injeção como sinal.

    A validação estrutural (regex) já bloquearia, mas falhar com
    "Caractere proibido" é mais educativo no log e nos testes.
    """
    if not isinstance(value, str):
        return value
    forbidden = (
        "<", ">", "{", "}", "$(", "${", "&&", "||", ";--", "/*", "*/",
        "\\x", "‮",  # RTL override
    )
    lower = value.lower()
    sql_keywords = (
        "' or ", "\" or ", " union ", " select ", "drop table",
        "insert into", "update ", " --",
    )
    for needle in forbidden:
        if needle in value:
            raise ValueError(f"Caractere/sequência não permitido: {needle!r}")
    for kw in sql_keywords:
        if kw in lower:
            raise ValueError("Padrão de injeção detectado")
    return value


# ─── Tipos prontos ────────────────────────────────────────────────────

SafeName = Annotated[
    str,
    BeforeValidator(_normalize_unicode),
    BeforeValidator(_reject_dangerous),
    StringConstraints(min_length=1, max_length=96, pattern=SAFE_NAME_RE.pattern),
]

SafeCode = Annotated[
    str,
    BeforeValidator(_normalize_unicode),
    StringConstraints(min_length=1, max_length=32, pattern=SAFE_CODE_RE.pattern),
]

SafeText = Annotated[
    str,
    BeforeValidator(_normalize_unicode),
    BeforeValidator(_reject_dangerous),
    StringConstraints(min_length=0, max_length=512),
]

PositiveInt = Annotated[int, Field(ge=1, le=10_000_000)]
ScoreInt = Annotated[int, Field(ge=0, le=100)]
PriceFloat = Annotated[float, Field(ge=0, le=10_000_000)]
HorsepowerInt = Annotated[int, Field(ge=1, le=2000)]
YearInt = Annotated[int, Field(ge=1990, le=2100)]
