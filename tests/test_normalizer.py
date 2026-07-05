from datetime import datetime, timezone

import pytest

from app.core.models import Severity
from app.modules.enrichment.normalizer import (
    cvss_to_severity,
    normalize_nvd_item,
)
from app.modules.ingestion.schemas import NvdCveItem


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, None),
        (2.5, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_cvss_to_severity_thresholds(score, expected):
    assert cvss_to_severity(score) == expected


def _sample_nvd_item(**overrides) -> dict:
    base = {
        "id": "CVE-2024-99999",
        "descriptions": [
            {"lang": "en", "value": "A critical remote code execution flaw in ExampleApp."},
            {"lang": "es", "value": "Una falla critica..."},
        ],
        "published": "2024-03-01T00:00:00.000",
        "lastModified": "2024-03-02T00:00:00.000",
        "metrics": {
            "cvssMetricV31": [{"baseScore": 9.8}],
        },
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-78"}]},
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:example:exampleapp:1.0:*:*:*:*:*:*:*", "vulnerable": True},
                            {"criteria": "cpe:2.3:a:example:exampleapp:0.9:*:*:*:*:*:*:*", "vulnerable": False},
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.com/advisory", "tags": ["vendor-advisory"]}],
    }
    base.update(overrides)
    return base


def test_normalize_nvd_item_full_record():
    item = NvdCveItem.model_validate(_sample_nvd_item())
    result = normalize_nvd_item(item)

    assert result["cve_id"] == "CVE-2024-99999"
    assert result["source"] == "nvd"
    assert result["description"].startswith("A critical remote code execution")
    assert result["cvss_score"] == 9.8
    assert result["severity"] == Severity.CRITICAL
    assert result["cwe_ids"] == ["CWE-78"]
    # Only the `vulnerable: True` CPE should be included.
    assert result["affected_cpes"] == ["cpe:2.3:a:example:exampleapp:1.0:*:*:*:*:*:*:*"]
    assert result["published_at"] == datetime(2024, 3, 1, 0, 0, 0)


def test_normalize_prefers_english_description():
    item = NvdCveItem.model_validate(_sample_nvd_item(
        descriptions=[
            {"lang": "es", "value": "Solo en espanol"},
            {"lang": "en", "value": "English description here"},
        ]
    ))
    result = normalize_nvd_item(item)
    assert result["description"] == "English description here"


def test_normalize_handles_missing_cvss():
    item = NvdCveItem.model_validate(_sample_nvd_item(metrics={}))
    result = normalize_nvd_item(item)
    assert result["cvss_score"] is None
    assert result["severity"] is None


def test_normalize_falls_back_to_v2_cvss_when_v31_absent():
    item = NvdCveItem.model_validate(_sample_nvd_item(
        metrics={"cvssMetricV2": [{"baseScore": 5.0}]}
    ))
    result = normalize_nvd_item(item)
    assert result["cvss_score"] == 5.0
    assert result["severity"] == Severity.MEDIUM


def test_normalize_handles_no_cwe_or_cpe_data():
    item = NvdCveItem.model_validate(_sample_nvd_item(weaknesses=[], configurations=[]))
    result = normalize_nvd_item(item)
    assert result["cwe_ids"] == []
    assert result["affected_cpes"] == []


def test_normalize_dedups_repeated_cwe_across_weaknesses():
    item = NvdCveItem.model_validate(_sample_nvd_item(weaknesses=[
        {"description": [{"lang": "en", "value": "CWE-78"}]},
        {"description": [{"lang": "en", "value": "CWE-78"}]},
        {"description": [{"lang": "en", "value": "CWE-89"}]},
    ]))
    result = normalize_nvd_item(item)
    assert result["cwe_ids"] == ["CWE-78", "CWE-89"]
