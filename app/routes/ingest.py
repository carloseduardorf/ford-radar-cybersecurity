"""
Webhook de ingestão (n8n → API), protegido por HMAC + integridade de payload.

Por que não usar JWT aqui:
- O n8n é uma aplicação, não um humano. Compartilhar JWT seria um pesadelo
  de rotação. HMAC com segredo dedicado é mais simples e mais seguro.

Anti-replay:
- Timestamp dentro da janela de tolerância.
- SHA256 do conteúdo da planilha — se já existe, retornamos 409.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import write_audit
from app.database import get_session
from app.models.competitor import Competitor
from app.models.spreadsheet import SpreadsheetIngest
from app.schemas.spreadsheet import SpreadsheetIngestRequest, SpreadsheetIngestResponse
from app.security.hmac_sign import verify_signature

router = APIRouter(prefix="/v1", tags=["ingest"])


@router.post(
    "/ingest/spreadsheet",
    response_model=SpreadsheetIngestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_spreadsheet(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Recebe payload assinado pelo n8n com linhas já parseadas da planilha."""
    raw = await request.body()
    sig_header = request.headers.get("x-signature")

    # 1) HMAC + janela temporal
    verify_signature(raw, sig_header)  # SignatureError tratado pelo handler

    # 2) Parse + validação Pydantic (schema strict)
    try:
        payload = SpreadsheetIngestRequest.model_validate_json(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Payload inválido")

    # 3) Idempotência via SHA256
    existing = await session.scalar(
        select(SpreadsheetIngest).where(SpreadsheetIngest.sha256 == payload.sha256)
    )
    if existing:
        raise HTTPException(status_code=409, detail="Planilha já processada")

    # 4) Persistir competidores em transação
    rid = getattr(request.state, "request_id", None)
    ingest = SpreadsheetIngest(
        filename=payload.filename,
        sha256=payload.sha256,
        size_bytes=len(raw),
        rows_processed=0,
        submitted_by_pseudonym="webhook:n8n",
        status="processing",
    )
    session.add(ingest)
    await session.flush()

    for row in payload.rows:
        comp = Competitor(
            brand=row.brand,
            model=row.model,
            version=row.version,
            year=row.year,
            horsepower=row.horsepower,
            price_brl=row.price_brl,
            fipe_code=row.fipe_code,
        )
        session.add(comp)

    ingest.rows_processed = len(payload.rows)
    ingest.status = "received"

    await write_audit(
        session,
        action="ingest.spreadsheet",
        resource="spreadsheet",
        resource_id=str(ingest.id),
        outcome="success",
        actor_pseudonym="webhook:n8n",
        ip=request.client.host if request.client else None,
        request_id=rid,
        detail=f"rows={len(payload.rows)} sha256={payload.sha256[:16]}...",
    )
    await session.commit()
    return SpreadsheetIngestResponse(
        ingest_id=ingest.id,
        rows_processed=ingest.rows_processed,
        status=ingest.status,
    )
