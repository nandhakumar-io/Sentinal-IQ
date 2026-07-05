"""
Centralized application configuration.
Loaded once, imported everywhere via `from app.core.config import settings`.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    app_name: str = "vuln-registry"
    environment: str = "development"
    debug: bool = True

    # Database
    database_url: str = "postgresql+asyncpg://vuln:vuln@localhost:5432/vuln_registry"

    # Search
    opensearch_url: str = "http://localhost:9200"

    # Queue
    redis_url: str = "redis://localhost:6379/0"

    # Auth
    jwt_secret: str = "change-me-in-prod"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None

    # External vuln feeds
    nvd_api_key: str | None = None
    osv_api_url: str = "https://api.osv.dev/v1"

    # NLQ / LLM
    llm_api_key: str | None = None
    llm_model: str = "claude-sonnet-5"

    # Multi-tenancy
    default_tenant_isolation: str = "row_level_security"  # or "schema" or "database"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
