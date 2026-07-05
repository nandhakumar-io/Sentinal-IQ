"""
Orchestrates the full ingestion flow: fetch from NVD, normalize, and
upsert into the Vulnerability table, deduplicating on cve_id.

This is the single entrypoint the scheduler (Celery beat / k8s CronJob) and
the manual CLI script both call — keeping the flow in one place means the
scheduled job and any manual "backfill last N days" run behave identically.
"""
import logging

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import Vulnerability
from app.modules.enrichment.normalizer import normalize_nvd_item
from app.modules.ingestion.nvd_client import NvdClient

logger = logging.getLogger(__name__)


async def upsert_vulnerabilities(db: AsyncSession, records: list[dict]) -> int:
    """
    Upserts normalized vulnerability dicts, keyed on the unique `cve_id`.
    On conflict, updates the mutable fields (a CVE's CVSS score/description
    can be revised by NVD after initial publication) but leaves `id` and
    `ingested_at` untouched.
    """
    if not records:
        return 0

    stmt = pg_insert(Vulnerability).values(records)
    update_cols = {
        "title": stmt.excluded.title,
        "description": stmt.excluded.description,
        "cvss_score": stmt.excluded.cvss_score,
        "severity": stmt.excluded.severity,
        "cwe_ids": stmt.excluded.cwe_ids,
        "affected_cpes": stmt.excluded.affected_cpes,
        "raw_payload": stmt.excluded.raw_payload,
        "published_at": stmt.excluded.published_at,
    }
    stmt = stmt.on_conflict_do_update(index_elements=["cve_id"], set_=update_cols)
    await db.execute(stmt)
    await db.commit()
    return len(records)


async def ingest_recent_nvd_cves(
    db: AsyncSession,
    modified_since: str | None = None,
    modified_until: str | None = None,
    max_results: int | None = None,
) -> int:
    """
    Full pipeline: fetch NVD CVEs (validated) -> normalize -> upsert.
    Returns the number of records written.
    """
    client = NvdClient()
    items = await client.fetch_cves(
        modified_since=modified_since,
        modified_until=modified_until,
        max_results=max_results,
    )
    logger.info("Fetched %d CVE items from NVD", len(items))

    records = [normalize_nvd_item(item) for item in items]
    written = await upsert_vulnerabilities(db, records)
    logger.info("Upserted %d vulnerability records", written)
    return written
