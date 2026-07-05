"""
Queue consumer: reads raw payloads from `raw-vulns` stream, normalizes,
persists, and triggers correlation + notifications.

Run separately from the API process: `python -m app.workers.ingestion_worker`
This is the piece most likely to need independent scaling (bursty ingestion
volume vs. steady query load), which is why it's already isolated as its
own process/deployment even inside the "modular monolith" repo.
"""
import asyncio

from app.core.db import AsyncSessionLocal
from app.modules.enrichment.normalizer import correlate_with_assets, normalize_nvd_payload


async def consume_loop():
    """
    TODO: subscribe to Redis Stream / Kafka topic `raw-vulns`, for each
    message: normalize -> upsert Vulnerability -> correlate_with_assets.
    """
    while True:
        await asyncio.sleep(5)  # placeholder poll interval


if __name__ == "__main__":
    asyncio.run(consume_loop())
