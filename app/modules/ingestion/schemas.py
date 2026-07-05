"""
Validates the shape of NVD API responses before we trust them. NVD's JSON is
deeply nested and has changed shape across API versions before — validating
at the boundary means a malformed/unexpected upstream response fails loudly
here, instead of silently producing a half-populated Vulnerability row.

We only model the fields we actually consume. Unknown extra fields are
ignored (`extra="ignore"`), since NVD adds fields over time and we don't
want to break ingestion every time they do.
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class NvdCvssData(BaseModel):
    model_config = ConfigDict(extra="ignore")
    base_score: float = Field(alias="baseScore")

class NvdCvssMetricV31(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cvss_data: NvdCvssData = Field(alias="cvssData")

    @property
    def base_score(self) -> float:
        return self.cvss_data.base_score


class NvdMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cvss_metric_v31: list[NvdCvssMetricV31] | None = Field(default=None, alias="cvssMetricV31")
    cvss_metric_v30: list[NvdCvssMetricV31] | None = Field(default=None, alias="cvssMetricV30")
    cvss_metric_v2: list[NvdCvssMetricV31] | None = Field(default=None, alias="cvssMetricV2")


class NvdDescription(BaseModel):
    model_config = ConfigDict(extra="ignore")
    lang: str
    value: str


class NvdWeakness(BaseModel):
    model_config = ConfigDict(extra="ignore")
    description: list[NvdDescription]


class NvdCpeMatch(BaseModel):
    model_config = ConfigDict(extra="ignore")
    criteria: str
    vulnerable: bool = True


class NvdConfigNode(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cpe_match: list[NvdCpeMatch] = Field(default_factory=list, alias="cpeMatch")


class NvdConfiguration(BaseModel):
    model_config = ConfigDict(extra="ignore")
    nodes: list[NvdConfigNode] = Field(default_factory=list)


class NvdReference(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str
    tags: list[str] = Field(default_factory=list)


class NvdCveItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str  # e.g. "CVE-2024-12345"
    descriptions: list[NvdDescription]
    published: datetime
    last_modified: datetime = Field(alias="lastModified")
    metrics: NvdMetrics = Field(default_factory=NvdMetrics)
    weaknesses: list[NvdWeakness] = Field(default_factory=list)
    configurations: list[NvdConfiguration] = Field(default_factory=list)
    references: list[NvdReference] = Field(default_factory=list)


class NvdVulnerabilityWrapper(BaseModel):
    """NVD wraps each CVE item in a `{"cve": {...}}` envelope."""
    model_config = ConfigDict(extra="ignore")
    cve: NvdCveItem


class NvdApiResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    vulnerabilities: list[NvdVulnerabilityWrapper] = Field(default_factory=list)
