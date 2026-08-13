import asyncio
import os
from collections.abc import AsyncGenerator, Generator

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from app.core.config import get_settings


@pytest.fixture(scope="session")
def postgres_container() -> Generator[PostgresContainer]:
    with PostgresContainer("postgres:16", driver="asyncpg") as container:
        yield container


@pytest.fixture(scope="session")
def redis_container() -> Generator[RedisContainer]:
    with RedisContainer("redis:7-alpine") as container:
        yield container


@pytest.fixture(scope="session")
def db_engine(postgres_container: PostgresContainer) -> Generator[AsyncEngine]:
    """Runs the real Alembic migration chain against a throwaway Postgres once
    per test session, so tests exercise the same schema path as production
    rather than an ORM-generated shortcut."""
    os.environ["DATABASE_URL"] = postgres_container.get_connection_url()
    get_settings.cache_clear()

    command.upgrade(Config("alembic.ini"), "head")

    engine = create_async_engine(postgres_container.get_connection_url(), pool_pre_ping=True)
    yield engine
    asyncio.run(engine.dispose())

    os.environ.pop("DATABASE_URL", None)
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def configured_app(
    postgres_container: PostgresContainer, redis_container: RedisContainer, db_engine: AsyncEngine
) -> AsyncGenerator[None]:
    """Points Settings at the shared migrated Postgres/Redis containers for the
    duration of one test. db_engine is depended on purely to force migrations
    to run first."""
    os.environ["DATABASE_URL"] = postgres_container.get_connection_url()
    redis_url = (
        f"redis://{redis_container.get_container_host_ip()}:"
        f"{redis_container.get_exposed_port(6379)}/0"
    )
    os.environ["REDIS_URL"] = redis_url
    get_settings.cache_clear()

    # Rate-limit counters must not leak between tests sharing this Redis
    # container, or later tests silently start seeing 429s from earlier ones.
    client = redis_asyncio.from_url(redis_url)  # type: ignore[no-untyped-call]
    await client.flushdb()
    await client.aclose()

    yield
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def db_session(db_engine: AsyncEngine) -> AsyncGenerator[AsyncSession]:
    """A plain session against the shared schema for test setup/assertions -
    not isolated per test, so tests must use unique data (e.g. random emails)
    rather than relying on rollback between tests."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
