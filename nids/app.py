"""ASGI entrypoint: load config, open DB, start ingest engine, serve dashboard."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from .api import build_app
from .config import Settings, load_settings
from .db import Store
from .demo import load_demo
from .engine import Engine
from .util import setup_logging

log = logging.getLogger("nids")

settings: Settings
store: Store
engine: Engine
app: FastAPI


def create_app() -> FastAPI:
    global settings, store, engine, app
    settings = load_settings()
    setup_logging(settings.log_path)
    store = Store(settings.db_path)
    engine = Engine(settings, store)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        log.info("starting 9yards NIDS on %s:%s (db=%s)", settings.host, settings.port, settings.db_path)
        n = store.scalar("SELECT COUNT(*) FROM packets")
        if settings.autoload_demo and n == 0:
            stats = load_demo(store, payload=settings.payload_enabled)
            log.info("auto-loaded DEMO dataset: %s", stats)
        engine.start()
        yield
        engine.stop()
        store.close()
        log.info("stopped")

    app = build_app(settings, store, engine, lifespan=lifespan)
    return app


app = create_app()


def main() -> None:
    s = load_settings()
    uvicorn.run(
        "nids.app:app",
        host=s.host,
        port=s.port,
        log_level="info",
        reload=False,
        ws="auto",
    )


if __name__ == "__main__":
    main()
