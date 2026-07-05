"""
Tests for NvdClient using respx-mocked HTTP responses (never hits the real
NVD API — NVD is not in the sandbox's allowed egress list, and hitting a
live external API in unit tests is bad practice anyway: slow, flaky,
rate-limited, and non-reproducible).
"""
import httpx
import pytest
import respx

from app.modules.ingestion.nvd_client import NVD_BASE_URL, NvdApiError, NvdClient

pytestmark = pytest.mark.asyncio


def _cve_wrapper(cve_id: str) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "metrics": {"cvssMetricV31": [{"baseScore": 7.5}]},
            "weaknesses": [],
            "configurations": [],
            "references": [],
        }
    }


def _page(vulns: list[dict], start_index: int, total_results: int, results_per_page: int) -> dict:
    return {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "totalResults": total_results,
        "vulnerabilities": vulns,
    }


@respx.mock
async def test_fetch_cves_single_page_no_pagination_needed():
    route = respx.get(NVD_BASE_URL).mock(
        return_value=httpx.Response(
            200, json=_page([_cve_wrapper("CVE-2024-0001"), _cve_wrapper("CVE-2024-0002")],
                             start_index=0, total_results=2, results_per_page=200)
        )
    )
    client = NvdClient(api_key="test-key")
    items = await client.fetch_cves()

    assert route.call_count == 1
    assert [i.id for i in items] == ["CVE-2024-0001", "CVE-2024-0002"]


@respx.mock
async def test_fetch_cves_paginates_across_multiple_pages():
    # total_results=5, page size 2 -> 3 pages: [0,1], [2,3], [4]
    route = respx.get(NVD_BASE_URL)
    route.side_effect = [
        httpx.Response(200, json=_page([_cve_wrapper("CVE-1"), _cve_wrapper("CVE-2")], 0, 5, 2)),
        httpx.Response(200, json=_page([_cve_wrapper("CVE-3"), _cve_wrapper("CVE-4")], 2, 5, 2)),
        httpx.Response(200, json=_page([_cve_wrapper("CVE-5")], 4, 5, 2)),
    ]
    client = NvdClient(api_key="test-key")
    items = await client.fetch_cves()

    assert route.call_count == 3
    assert [i.id for i in items] == ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"]


@respx.mock
async def test_fetch_cves_respects_max_results_and_stops_early():
    route = respx.get(NVD_BASE_URL)
    route.side_effect = [
        httpx.Response(200, json=_page([_cve_wrapper("CVE-1"), _cve_wrapper("CVE-2")], 0, 10, 2)),
    ]
    client = NvdClient(api_key="test-key")
    items = await client.fetch_cves(max_results=2)

    assert route.call_count == 1  # must not fetch page 2 once max_results is hit
    assert len(items) == 2


@respx.mock
async def test_fetch_cves_retries_on_429_then_succeeds():
    route = respx.get(NVD_BASE_URL)
    route.side_effect = [
        httpx.Response(429, text="rate limited"),
        httpx.Response(200, json=_page([_cve_wrapper("CVE-1")], 0, 1, 200)),
    ]
    client = NvdClient(api_key="test-key")
    # Patch sleep so the test doesn't actually wait through the backoff.
    import app.modules.ingestion.nvd_client as nvd_client_module
    original_sleep = nvd_client_module.asyncio.sleep
    nvd_client_module.asyncio.sleep = lambda *_a, **_k: original_sleep(0)

    try:
        items = await client.fetch_cves()
    finally:
        nvd_client_module.asyncio.sleep = original_sleep

    assert route.call_count == 2
    assert [i.id for i in items] == ["CVE-1"]


@respx.mock
async def test_fetch_cves_raises_after_exhausting_retries():
    route = respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(503, text="unavailable"))
    client = NvdClient(api_key="test-key")

    import app.modules.ingestion.nvd_client as nvd_client_module
    original_sleep = nvd_client_module.asyncio.sleep
    nvd_client_module.asyncio.sleep = lambda *_a, **_k: original_sleep(0)

    try:
        with pytest.raises(NvdApiError):
            await client.fetch_cves()
    finally:
        nvd_client_module.asyncio.sleep = original_sleep

    assert route.call_count == 5  # MAX_RETRIES


@respx.mock
async def test_fetch_cves_raises_immediately_on_non_retryable_4xx():
    route = respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(400, text="bad request"))
    client = NvdClient(api_key="test-key")

    with pytest.raises(NvdApiError):
        await client.fetch_cves()

    assert route.call_count == 1  # no retries wasted on a genuinely bad request


async def test_fetch_cves_rejects_one_sided_date_range():
    client = NvdClient(api_key="test-key")
    with pytest.raises(ValueError):
        await client.fetch_cves(modified_since="2024-01-01T00:00:00.000Z")


@respx.mock
async def test_fetch_cves_sends_date_range_params_when_both_provided():
    route = respx.get(NVD_BASE_URL).mock(
        return_value=httpx.Response(200, json=_page([], 0, 0, 200))
    )
    client = NvdClient(api_key="test-key")
    await client.fetch_cves(
        modified_since="2024-01-01T00:00:00.000Z",
        modified_until="2024-01-02T00:00:00.000Z",
    )

    sent_params = dict(route.calls.last.request.url.params)
    assert sent_params["lastModStartDate"] == "2024-01-01T00:00:00.000Z"
    assert sent_params["lastModEndDate"] == "2024-01-02T00:00:00.000Z"


@respx.mock
async def test_fetch_cves_sends_api_key_header_when_configured():
    route = respx.get(NVD_BASE_URL).mock(
        return_value=httpx.Response(200, json=_page([], 0, 0, 200))
    )
    client = NvdClient(api_key="my-secret-key")
    await client.fetch_cves()

    assert route.calls.last.request.headers.get("apikey") == "my-secret-key"


@respx.mock
async def test_fetch_cves_no_api_key_sends_no_header():
    route = respx.get(NVD_BASE_URL).mock(
        return_value=httpx.Response(200, json=_page([], 0, 0, 200))
    )
    client = NvdClient(api_key=None)
    await client.fetch_cves()

    assert "apikey" not in route.calls.last.request.headers
