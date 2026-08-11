from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI

from app.api.errors import register_exception_handlers
from app.api.health import router as health_router
from app.api.middleware import RequestIDMiddleware
from app.core.config import get_settings
from app.core.database import make_engine
from app.core.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    configure_logging()
    settings = get_settings()
    app.state.db_engine = make_engine(settings.database_url)
    # redis-py ships py.typed but Redis.from_url itself isn't fully annotated upstream.
    app.state.redis = redis.from_url(settings.redis_url)  # type: ignore[no-untyped-call]
    yield
    await app.state.redis.aclose()
    await app.state.db_engine.dispose()


app = FastAPI(title="Bekaa3D API", version="0.1.0", lifespan=lifespan)

app.add_middleware(RequestIDMiddleware)
register_exception_handlers(app)
app.include_router(health_router)
