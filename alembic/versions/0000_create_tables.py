"""create initial tables

Revision ID: 0000
Revises:
Create Date: 2026-07-05
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0000"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    severity_enum = postgresql.ENUM(
        "low", "medium", "high", "critical", name="severity", create_type=True
    )
    role_enum = postgresql.ENUM(
        "admin", "analyst", "viewer", name="role", create_type=True
    )
    severity_enum.create(op.get_bind(), checkfirst=True)
    role_enum.create(op.get_bind(), checkfirst=True)

    # Re-declare with create_type=False: the types already exist (created above),
    # and without this, SQLAlchemy tries to CREATE TYPE again the first time each
    # enum is used in a table's column definition, causing a DuplicateObjectError.
    severity_enum = postgresql.ENUM(
        "low", "medium", "high", "critical", name="severity", create_type=False
    )
    role_enum = postgresql.ENUM(
        "admin", "analyst", "viewer", name="role", create_type=False
    )

    op.create_table(
        "institutions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("oidc_domain", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("institutions.id"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role", role_enum, nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("institutions.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("cpe", sa.String(500), nullable=True),
        sa.Column("asset_type", sa.String(50), nullable=False, server_default="host"),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cve_id", sa.String(30), nullable=True, unique=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("severity", severity_enum, nullable=True),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("affected_cpes", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("raw_payload", postgresql.JSONB(), nullable=True),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("embedding", postgresql.ARRAY(sa.Float()), nullable=True),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])

    op.create_table(
        "vulnerability_references",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("url", sa.String(1000), nullable=False),
        sa.Column("ref_type", sa.String(50), nullable=False),
    )

    op.create_table(
        "asset_vulnerability_matches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("institutions.id"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("match_confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("detected_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("asset_vulnerability_matches")
    op.drop_table("vulnerability_references")
    op.drop_index("ix_vulnerabilities_cve_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_table("assets")
    op.drop_table("users")
    op.drop_table("institutions")

    postgresql.ENUM(name="role").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="severity").drop(op.get_bind(), checkfirst=True)