import logging

import asyncpg
from fastapi import FastAPI

from app.config import Settings
from app.messaging import connect, decode, subscribe
from app.router.health import router as health_router
from app.service.scanner import process_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="nuclei-worker", docs_url=None, redoc_url=None)
app.include_router(health_router)


@app.on_event("startup")
async def startup() -> None:
    cfg = Settings()
    app.state.config = cfg
    app.state.db = await asyncpg.create_pool(cfg.database_url, min_size=2, max_size=10)
    app.state.nc, app.state.js = await connect(cfg.nats_url)

    async def handle(msg) -> None:
        try:
            payload = decode(msg.data)
            logger.info("received scan %s target=%s", payload.get("scan_id"), payload.get("target"))
            await process_scan(app.state.db, payload)
            await msg.ack()
        except Exception as exc:
            logger.error("failed to process scan: %s", exc)
            await msg.nak()

    await subscribe(app.state.js, handle)
    logger.info("nuclei-worker ready")


@app.on_event("shutdown")
async def shutdown() -> None:
    nc = getattr(app.state, "nc", None)
    if nc:
        await nc.drain()
    db = getattr(app.state, "db", None)
    if db:
        await db.close()
