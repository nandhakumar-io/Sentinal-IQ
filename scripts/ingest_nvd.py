"""
Manual/scheduled entrypoint for NVD ingestion. Usage:

    python -m scripts.ingest_nvd --hours 24
    python -m scripts.ingest_nvd --since 2024-01-01T00:00:00.000Z --until 2024-01-05T00:00:00.000Z

Intended to be run as a k8s CronJob (e.g. every 2 hours) or manually for
backfills. Uses its own DB session since it runs outside the request cycle.
"""
import argparse
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.core.db import AsyncSessionLocal
from app.modules.ingestion.service import ingest_recent_nvd_cves

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


async def main(hours: int | None, since: str | None, until: str | None, max_results: int | None) -> None:
    if hours is not None:
        now = datetime.now(timezone.utc)
        since = _fmt(now - timedelta(hours=hours))
        until = _fmt(now)

    async with AsyncSessionLocal() as db:
        count = await ingest_recent_nvd_cves(
            db, modified_since=since, modified_until=until, max_results=max_results
        )
    logger.info("Ingestion complete: %d records written", count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest CVEs from NVD")
    parser.add_argument("--hours", type=int, default=24, help="Look back this many hours (default 24)")
    parser.add_argument("--since", type=str, default=None, help="ISO-8601 UTC start, overrides --hours")
    parser.add_argument("--until", type=str, default=None, help="ISO-8601 UTC end, required if --since is set")
    parser.add_argument("--max-results", type=int, default=None, help="Cap total records fetched (testing)")
    args = parser.parse_args()

    hours = None if args.since else args.hours
    asyncio.run(main(hours, args.since, args.until, args.max_results))
