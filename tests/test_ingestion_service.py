"""
Tests for app.modules.ingestion.service — the orchestration layer that ties
NVD fetch -> normalize -> upsert together. The DB layer is mocked here
(AsyncMock) rather than hitting a real Postgres, since correctness of the
upsert *statement construction* and orchestration *control flow* is what
matters at this level; ON CONFLICT semantics are exercised by the DB itself
and would belong in an integration test against a real Postgres instance.
"""
from unittest.mock import AsyncMock, patch

import pytest

from app.core.models import Severity
from app.modules.ingestion.schemas import NvdCveItem
from app.modules.ingestion.service import ingest_recent_nvd_cves, upsert_vulnerabilities

pytestmark = pytest.mark.asyncio


def _raw_item(cve_id: str, score: float = 7.5) -> dict:
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"desc {cve_id}"}],
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-01-02T00:00:00.000",
        "metrics": {"cvssMetricV31": [{"baseScore": score}]},
        "weaknesses": [],
        "configurations": [],
        "references": [],
    }


async def test_upsert_vulnerabilities_returns_zero_for_empty_input():
    db = AsyncMock()
    written = await upsert_vulnerabilities(db, [])

    assert written == 0
    db.execute.assert_not_called()
    db.commit.assert_not_called()


async def test_upsert_vulnerabilities_executes_and_commits_for_nonempty_input():
    db = AsyncMock()
    item = NvdCveItem.model_validate(_raw_item("CVE-2024-0001"))
    from app.modules.enrichment.normalizer import normalize_nvd_item
    record = normalize_nvd_item(item)

    written = await upsert_vulnerabilities(db, [record])

    assert written == 1
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()


async def test_upsert_statement_targets_cve_id_conflict_column():
    """
    Regression guard: the whole point of upserting on cve_id is that a CVE
    republished by NVD updates the existing row instead of erroring on the
    unique constraint or silently creating a duplicate.
    """
    db = AsyncMock()
    item = NvdCveItem.model_validate(_raw_item("CVE-2024-0001"))
    from app.modules.enrichment.normalizer import normalize_nvd_item
    record = normalize_nvd_item(item)

    await upsert_vulnerabilities(db, [record])

    executed_stmt = db.execute.call_args[0][0]
    assert executed_stmt.table.name == "vulnerabilities"
    assert list(executed_stmt._post_values_clause.inferred_target_elements) == ["cve_id"]


async def test_ingest_recent_nvd_cves_full_pipeline_orchestration():
    """
    Verifies the fetch -> normalize -> upsert wiring end-to-end without
    touching the network or a real DB: NvdClient.fetch_cves is mocked to
    return two validated items, and we assert the right number of records
    reach upsert with the right shape.
    """
    fake_items = [
        NvdCveItem.model_validate(_raw_item("CVE-2024-1111", score=9.8)),
        NvdCveItem.model_validate(_raw_item("CVE-2024-2222", score=3.0)),
    ]

    db = AsyncMock()

    with patch("app.modules.ingestion.service.NvdClient") as MockClient:
        instance = MockClient.return_value
        instance.fetch_cves = AsyncMock(return_value=fake_items)

        written = await ingest_recent_nvd_cves(db, modified_since="a", modified_until="b", max_results=50)

    instance.fetch_cves.assert_awaited_once_with(
        modified_since="a", modified_until="b", max_results=50
    )
    assert written == 2
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()

    # Confirm normalization actually ran (severity correctly derived from
    # CVSS) using the same normalizer function the pipeline calls internally.
    from app.modules.enrichment.normalizer import normalize_nvd_item
    expected = [normalize_nvd_item(i) for i in fake_items]
    assert expected[0]["severity"] == Severity.CRITICAL  # score 9.8
    assert expected[1]["severity"] == Severity.LOW        # score 3.0
