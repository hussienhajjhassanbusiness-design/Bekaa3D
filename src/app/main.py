from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, Request
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import make_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    settings = get_settings()
    app.state.db_engine = make_engine(settings.database_url)
    # redis-py ships py.typed but Redis.from_url itself isn't fully annotated upstream.
    app.state.redis = redis.from_url(settings.redis_url)  # type: ignore[no-untyped-call]
    yield
    await app.state.redis.aclose()
    await app.state.db_engine.dispose()


app = FastAPI(title="Bekaa3D API", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health(request: Request) -> dict[str, str]:
    async with request.app.state.db_engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await request.app.state.redis.ping()
    return {"status": "ok"}
