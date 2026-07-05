"""
Core data model.

Institution (tenant)
  1---N Asset               (an institution's inventory: servers, software, etc.)
  1---N User                (institution staff, role-scoped)

Vulnerability                (global, sourced from external feeds - NOT tenant-scoped)
  1---N VulnerabilityReference (CVE links, vendor advisories, patches)

AssetVulnerabilityMatch      (join table: which assets are affected by which vulns)
  N---1 Asset (tenant-scoped)
  N---1 Vulnerability (global)

Every tenant-scoped table carries `tenant_id` + has an RLS policy (see
alembic/versions/0001_row_level_security.py) so a query without the correct
session-level tenant context returns zero rows, even on a raw SQL mistake.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class Severity(str, PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Role(str, PyEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Institution(Base):
    """A tenant: a university, hospital, bank, gov agency, etc."""
    __tablename__ = "institutions"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    oidc_domain: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    users: Mapped[list["User"]] = relationship(back_populates="institution")
    assets: Mapped[list["Asset"]] = relationship(back_populates="institution")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("institutions.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(
        Enum(Role, values_callable=lambda enum_cls: [e.value for e in enum_cls]),
        default=Role.VIEWER,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    institution: Mapped["Institution"] = relationship(back_populates="users")


class Asset(Base):
    """A tenant's inventory item: a host, service, or software package."""
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("institutions.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    cpe: Mapped[str | None] = mapped_column(String(500))  # Common Platform Enumeration
    asset_type: Mapped[str] = mapped_column(String(50), default="host")
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    institution: Mapped["Institution"] = relationship(back_populates="assets")
    matches: Mapped[list["AssetVulnerabilityMatch"]] = relationship(back_populates="asset")


class Vulnerability(Base):
    """Global vuln record, sourced from NVD/OSV/MITRE/vendor feeds. Not tenant-scoped."""
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = uuid_pk()
    cve_id: Mapped[str | None] = mapped_column(String(30), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(50))  # nvd | osv | vendor:xyz
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, values_callable=lambda enum_cls: [e.value for e in enum_cls])
    )
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    affected_cpes: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    raw_payload: Mapped[dict | None] = mapped_column(JSONB)  # original feed payload
    published_at: Mapped[datetime | None] = mapped_column(DateTime)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    embedding: Mapped[list[float] | None] = mapped_column(ARRAY(Float))  # pgvector in prod

    references: Mapped[list["VulnerabilityReference"]] = relationship(back_populates="vulnerability")
    matches: Mapped[list["AssetVulnerabilityMatch"]] = relationship(back_populates="vulnerability")


class VulnerabilityReference(Base):
    """Links, advisories, patches associated with a vulnerability."""
    __tablename__ = "vulnerability_references"

    id: Mapped[uuid.UUID] = uuid_pk()
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"))
    url: Mapped[str] = mapped_column(String(1000))
    ref_type: Mapped[str] = mapped_column(String(50))  # advisory | patch | exploit | vendor

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="references")


class AssetVulnerabilityMatch(Base):
    """Correlation: this tenant's asset is affected by this vulnerability."""
    __tablename__ = "asset_vulnerability_matches"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("institutions.id"), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)
    match_confidence: Mapped[float] = mapped_column(Float, default=1.0)  # CPE-exact vs fuzzy match
    status: Mapped[str] = mapped_column(String(30), default="open")  # open | acknowledged | remediated
    detected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="matches")
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="matches")