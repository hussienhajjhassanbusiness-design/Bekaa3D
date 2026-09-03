from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI

from app.api.errors import register_exception_handlers
from app.api.health import router as health_router
from app.api.middleware import RequestIDMiddleware
from app.api.openapi import custom_openapi
from app.api.v1.router import router as v1_router
from app.core import models as _models  # noqa: F401 - registers models onto Base.metadata
from app.core.config import get_settings
from app.core.database import make_engine, make_session_factory
from app.core.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    configure_logging()
    settings = get_settings()
    app.state.db_engine = make_engine(settings.database_url)
    app.state.db_session_factory = make_session_factory(app.state.db_engine)
    # redis-py ships py.typed but Redis.from_url itself isn't fully annotated upstream.
    app.state.redis = redis.from_url(settings.redis_url)  # type: ignore[no-untyped-call]
    yield
    await app.state.redis.aclose()
    await app.state.db_engine.dispose()


app = FastAPI(title="Bekaa3D API", version="0.1.0", lifespan=lifespan)

app.add_middleware(RequestIDMiddleware)
register_exception_handlers(app)
app.include_router(health_router)
app.include_router(v1_router)

# VS-005: describe the cookie/CSRF/MFA security schemes in the generated
# OpenAPI document. Documentation only - no route's behaviour changes.
app.openapi = lambda: custom_openapi(app)  # type: ignore[method-assign]
