"""
Consumes validated NVD CVE items, normalizes into the internal Vulnerability
schema, dedups against existing cve_id, and derives severity from CVSS.
"""
from app.core.models import Severity
from app.modules.ingestion.schemas import NvdCveItem

# CVSS thresholds per the official CVSS v3.x qualitative severity rating scale.
_SEVERITY_THRESHOLDS: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]


def cvss_to_severity(score: float) -> Severity | None:
    """CVSS 0.0 has no qualitative rating (informational-only); everything
    else maps per the standard v3.x scale."""
    if score <= 0.0:
        return None
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.LOW


def _best_cvss_score(item: NvdCveItem) -> float | None:
    """Prefer the newest CVSS version available (v3.1 > v3.0 > v2)."""
    for metric_list in (
        item.metrics.cvss_metric_v31,
        item.metrics.cvss_metric_v30,
        item.metrics.cvss_metric_v2,
    ):
        if metric_list:
            return metric_list[0].base_score
    return None


def _english_description(item: NvdCveItem) -> str:
    for desc in item.descriptions:
        if desc.lang == "en":
            return desc.value
    # Fall back to whatever's available rather than dropping the record.
    return item.descriptions[0].value if item.descriptions else ""


def _extract_cwe_ids(item: NvdCveItem) -> list[str]:
    cwe_ids: list[str] = []
    for weakness in item.weaknesses:
        for desc in weakness.description:
            if desc.value.startswith("CWE-") and desc.value not in cwe_ids:
                cwe_ids.append(desc.value)
    return cwe_ids


def _extract_affected_cpes(item: NvdCveItem) -> list[str]:
    cpes: list[str] = []
    for config in item.configurations:
        for node in config.nodes:
            for match in node.cpe_match:
                if match.vulnerable and match.criteria not in cpes:
                    cpes.append(match.criteria)
    return cpes


def normalize_nvd_item(item: NvdCveItem) -> dict:
    """
    Maps a validated NVD CVE item into our flat Vulnerability fields.
    Returns a plain dict suitable for `Vulnerability(**normalize_nvd_item(item))`
    or as the values dict for an upsert statement.
    """
    cvss_score = _best_cvss_score(item)
    description = _english_description(item)

    return {
        "cve_id": item.id,
        "source": "nvd",
        "title": description[:500] if description else item.id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": cvss_to_severity(cvss_score) if cvss_score is not None else None,
        "cwe_ids": _extract_cwe_ids(item),
        "affected_cpes": _extract_affected_cpes(item),
        "raw_payload": item.model_dump(mode="json", by_alias=True),
        "published_at": item.published,
    }


async def correlate_with_assets(vulnerability_id: str) -> None:
    """
    TODO (next feature): for each tenant, match Vulnerability.affected_cpes
    against Asset.cpe (exact + fuzzy), create AssetVulnerabilityMatch rows,
    trigger notification if severity is HIGH/CRITICAL.
    """
    raise NotImplementedError
