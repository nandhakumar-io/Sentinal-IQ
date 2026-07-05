"""
Registry module: the core CRUD + query surface over vulnerabilities, assets,
and their correlation. This is what the NLQ service calls into as its
"ground truth" retrieval source.
"""
import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.models import Asset, AssetVulnerabilityMatch, Severity, Vulnerability
from app.core.security import AuthContext, get_current_auth

router = APIRouter(prefix="/registry", tags=["registry"])


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: Severity | None = None,
    cve_id: str | None = None,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    stmt = select(Vulnerability).limit(limit)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if cve_id:
        stmt = stmt.where(Vulnerability.cve_id == cve_id)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/assets/{asset_id}/vulnerabilities")
async def vulnerabilities_for_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """Tenant-scoped: RLS ensures this only returns rows for auth.tenant_id."""
    stmt = (
        select(Vulnerability)
        .join(AssetVulnerabilityMatch, AssetVulnerabilityMatch.vulnerability_id == Vulnerability.id)
        .where(AssetVulnerabilityMatch.asset_id == asset_id)
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/assets")
async def list_assets(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    result = await db.execute(select(Asset))
    return result.scalars().all()
