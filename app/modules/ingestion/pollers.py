"""
Feed pollers: pull from external vuln sources on a schedule (Celery beat / k8s
CronJob) and push raw payloads onto the queue for the normalization worker.
This is deliberately decoupled from enrichment/storage — pollers only fetch
and enqueue, they never write to the DB directly.
"""
import httpx

from app.core.config import settings


async def poll_nvd(modified_since: str | None = None) -> list[dict]:
    """Pull recently modified CVEs from the NVD API."""
    params = {"lastModStartDate": modified_since} if modified_since else {}
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])


async def poll_osv(ecosystem: str) -> list[dict]:
    """Pull vulnerabilities for a given package ecosystem from OSV."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{settings.osv_api_url}/query", timeout=30)
        resp.raise_for_status()
        return resp.json().get("vulns", [])


async def enqueue_raw_payloads(payloads: list[dict], source: str) -> None:
    """
    TODO: push each payload onto Redis Streams / Kafka topic `raw-vulns`
    with `source` tag, for the normalization worker to consume.
    """
    raise NotImplementedError
