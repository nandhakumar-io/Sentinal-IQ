"""
Async SQLAlchemy engine + session factory, plus a FastAPI dependency
that also sets the Postgres session variable used by row-level security
policies to enforce tenant isolation at the database layer.
"""
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

engine = create_async_engine(settings.database_url, echo=settings.debug, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db(tenant_id: str | None = None) -> AsyncGenerator[AsyncSession, None]:
    """
    Yields a DB session. If a tenant_id is present (set by tenancy middleware
    from the authenticated user's JWT), it's pushed into a Postgres session
    variable that RLS policies read via `current_setting('app.tenant_id')`.
    """
    async with AsyncSessionLocal() as session:
        if tenant_id:
            await session.execute(text("SET app.tenant_id = :tid"), {"tid": tenant_id})
        yield session
