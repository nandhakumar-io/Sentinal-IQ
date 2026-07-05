"""
NVD API client.

NVD's rate limits: 5 requests / 30s without an API key, 50 requests / 30s
with one (settings.nvd_api_key). We respect this with a minimum inter-request
delay, and back off with retries on 403/429 (NVD returns 403 for rate-limit
violations, not always 429) and on transient 5xx/network errors.

Pagination: NVD returns up to 2000 results per page (we ask for a smaller,
safer page size) with `startIndex`/`totalResults`. We page through until
we've collected everything or `max_results` is hit.
"""
import asyncio
import logging

import httpx

from app.core.config import settings
from app.modules.ingestion.schemas import NvdApiResponse, NvdCveItem

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 200
MAX_RETRIES = 5
BASE_BACKOFF_SECONDS = 2.0
# With an API key NVD allows ~50 req/30s (0.6s/req); without a key, 5 req/30s (6s/req).
MIN_REQUEST_INTERVAL = 0.65 if settings.nvd_api_key else 6.5


class NvdApiError(Exception):
    """Raised when NVD returns an unrecoverable error after retries are exhausted."""


class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: float = 30.0):
        self.api_key = api_key or settings.nvd_api_key
        self.timeout = timeout
        self._last_request_at: float = 0.0

    def _headers(self) -> dict:
        return {"apiKey": self.api_key} if self.api_key else {}

    async def _throttle(self) -> None:
        """Ensure we never exceed NVD's rate limit, regardless of caller behavior."""
        elapsed = asyncio.get_event_loop().time() - self._last_request_at
        wait = MIN_REQUEST_INTERVAL - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_at = asyncio.get_event_loop().time()

    async def _get_page(self, client: httpx.AsyncClient, params: dict) -> NvdApiResponse:
        last_exc: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            await self._throttle()
            try:
                resp = await client.get(NVD_BASE_URL, params=params, headers=self._headers())
            except httpx.TransportError as e:
                last_exc = e
                logger.warning("NVD request transport error (attempt %d/%d): %s", attempt, MAX_RETRIES, e)
                await asyncio.sleep(BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))
                continue

            if resp.status_code == 200:
                return NvdApiResponse.model_validate(resp.json())

            if resp.status_code in (403, 429, 503):
                # Rate-limited or transiently unavailable — back off and retry.
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if retry_after else BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                logger.warning(
                    "NVD returned %d (attempt %d/%d), backing off %.1fs",
                    resp.status_code, attempt, MAX_RETRIES, delay,
                )
                await asyncio.sleep(delay)
                last_exc = NvdApiError(f"NVD returned {resp.status_code}: {resp.text[:500]}")
                continue

            # 4xx other than the above is not retryable (bad request, bad params, etc.)
            raise NvdApiError(f"NVD returned unrecoverable {resp.status_code}: {resp.text[:500]}")

        raise NvdApiError(f"NVD request failed after {MAX_RETRIES} attempts") from last_exc

    async def fetch_cves(
        self,
        modified_since: str | None = None,
        modified_until: str | None = None,
        max_results: int | None = None,
    ) -> list[NvdCveItem]:
        """
        Fetch CVEs, paging through NVD's `startIndex`/`totalResults` mechanism.

        `modified_since`/`modified_until` must be ISO-8601 UTC timestamps
        (e.g. "2024-01-01T00:00:00.000Z"). NVD requires both to be set together
        and requires the date range to be at most 120 days.
        """
        items: list[NvdCveItem] = []
        start_index = 0

        params: dict = {"resultsPerPage": PAGE_SIZE, "startIndex": start_index}
        if modified_since and modified_until:
            params["lastModStartDate"] = modified_since
            params["lastModEndDate"] = modified_until
        elif modified_since or modified_until:
            raise ValueError("modified_since and modified_until must be provided together (NVD API requirement)")

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while True:
                params["startIndex"] = start_index
                page = await self._get_page(client, params)

                items.extend(w.cve for w in page.vulnerabilities)
                logger.info(
                    "NVD page fetched: startIndex=%d, got=%d, total=%d",
                    start_index, len(page.vulnerabilities), page.total_results,
                )

                if max_results is not None and len(items) >= max_results:
                    return items[:max_results]

                start_index += page.results_per_page
                if start_index >= page.total_results or not page.vulnerabilities:
                    break

        return items
