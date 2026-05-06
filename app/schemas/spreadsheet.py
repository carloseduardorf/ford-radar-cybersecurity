"""Schemas do webhook de ingestão (n8n → API)."""
from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import SafeName
from app.schemas.competitor import CompetitorIn


class SpreadsheetIngestRequest(BaseModel):
    """Payload assinado por HMAC enviado pelo n8n."""

    model_config = ConfigDict(extra="forbid")

    filename: SafeName = Field(..., max_length=255)
    sha256: str = Field(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    rows: List[CompetitorIn] = Field(..., min_length=1, max_length=5000)


class SpreadsheetIngestResponse(BaseModel):
    ingest_id: int
    rows_processed: int
    status: str
