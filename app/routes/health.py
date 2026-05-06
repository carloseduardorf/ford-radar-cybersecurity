"""Endpoints de health/readiness — sem auth, sem dados sensíveis."""
from __future__ import annotations

from fastapi import APIRouter

from app.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz():
    return {"status": "ok"}


@router.get("/readyz")
async def readyz():
    """Não vaza versão detalhada nem dependências internas."""
    s = get_settings()
    return {"status": "ready", "service": s.app_name}
