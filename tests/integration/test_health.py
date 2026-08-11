import os

import pytest
from fastapi.testclient import TestClient
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from app.core.config import get_settings


@pytest.mark.integration
def test_health_reports_ok_when_db_and_redis_are_reachable() -> None:
    with (
        PostgresContainer("postgres:16", driver="asyncpg") as postgres,
        RedisContainer("redis:7-alpine") as redis_server,
    ):
        os.environ["DATABASE_URL"] = postgres.get_connection_url()
        os.environ["REDIS_URL"] = (
            f"redis://{redis_server.get_container_host_ip()}:"
            f"{redis_server.get_exposed_port(6379)}/0"
        )
        get_settings.cache_clear()

        from app.main import app

        with TestClient(app) as client:
            response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

        get_settings.cache_clear()
