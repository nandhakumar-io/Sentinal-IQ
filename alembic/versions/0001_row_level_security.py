"""enable row-level security for tenant isolation

Revision ID: 0001
Revises:
Create Date: 2026-07-04
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TENANT_SCOPED_TABLES = ["assets", "users", "asset_vulnerability_matches"]


def upgrade() -> None:
    for table in TENANT_SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation_{table} ON {table}
            USING (tenant_id::text = current_setting('app.tenant_id', true))
        """)
        # Force RLS even for the table owner role (defense in depth)
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    for table in TENANT_SCOPED_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
