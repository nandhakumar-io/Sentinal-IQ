# Cloud-Native Centralized Vulnerability Registry & Intelligent Security Query Interface

## Architecture (structure)

**Modular monolith** for the core (auth, tenancy, registry CRUD, dashboards/API),
with two components pulled out as separate services from day one because their
scaling/operational profile is genuinely different:

- `ingestion` pipeline — async, queue-driven, bursty (feed pollers + workers)
- `nlq` service — natural-language query / RAG layer, latency-sensitive, calls
  external LLM APIs, iterates independently of core CRUD logic

Everything else lives in one deployable FastAPI app under `app/`, organized
into modules with clear internal boundaries so any of them can be extracted
into a standalone service later without a rewrite.

```
app/
  core/            # config, db session, security, tenancy middleware, logging
  modules/
    auth/           # OIDC/SSO, RBAC, tenant management
    registry/       # CVE/vuln CRUD, asset inventory, correlation
    enrichment/     # CVSS scoring, CPE/CWE mapping, dedup
    ingestion/      # feed pollers (NVD, OSV, MITRE, vendor feeds) -> queue producers
    nlq/            # RAG pipeline: embeddings, retrieval, LLM query answering
    notifications/  # alerting on new/critical vulns matching tenant assets
  workers/          # queue consumers (ingestion normalization, enrichment jobs)
  api/              # FastAPI routers, wired to modules
alembic/            # DB migrations
infra/
  docker/           # Dockerfiles
  k8s/               # k8s manifests (deployments, services, ingress) - added later
tests/
```

## Data model (see `app/core/models.py`)

Key relationships: `Institution (tenant)` 1---N `Asset` N---N `Vulnerability`
via `AssetVulnerabilityMatch`, with `Vulnerability` sourced from external feeds
and enriched with CVSS/CPE/CWE. Multi-tenancy enforced via `tenant_id` on every
tenant-scoped table + Postgres row-level security (see migration 0001).

## Local dev

```bash
cp .env.example .env
docker compose up -d db redis opensearch
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

## Tech stack

- **API**: FastAPI (Python) — async, good OpenAPI support for institution integrations
- **DB**: PostgreSQL (system of record, RLS for tenant isolation) + pgvector (embeddings)
- **Search**: OpenSearch (full-text/faceted CVE search)
- **Queue**: Redis Streams (dev) / SQS or Kafka (prod) for ingestion pipeline
- **Auth**: OIDC/SSO (via Authlib), JWT-based session, RBAC per institution
- **NLQ**: RAG — retrieve relevant CVE/advisory records, LLM summarizes only
  retrieved facts (no freehand security claims)
- **Observability**: OpenTelemetry from day one
- **Deploy**: Docker Compose locally → Kubernetes when multi-tenant scale demands it
