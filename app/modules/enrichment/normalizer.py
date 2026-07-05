"""
Consumes raw feed payloads (from queue), normalizes into the internal
Vulnerability schema, dedups against existing cve_id, computes/derives
severity from CVSS, and correlates against tenant asset CPEs to create
AssetVulnerabilityMatch rows.
"""
from app.core.models import Severity


def cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def normalize_nvd_payload(raw: dict) -> dict:
    """
    TODO: map NVD's nested CVE JSON shape into our flat Vulnerability fields
    (cve_id, title, description, cvss_score, severity, cwe_ids, affected_cpes).
    """
    raise NotImplementedError


async def correlate_with_assets(vulnerability_id: str) -> None:
    """
    TODO: for each tenant, match Vulnerability.affected_cpes against
    Asset.cpe (exact + fuzzy), create AssetVulnerabilityMatch rows,
    trigger notification if severity is HIGH/CRITICAL.
    """
    raise NotImplementedError
