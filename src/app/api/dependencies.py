from collections.abc import AsyncGenerator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession


async def get_session(request: Request) -> AsyncGenerator[AsyncSession]:
    """One transaction per request: everything a route does through this session
    commits or rolls back together (e.g. account creation + outbox insert must
    land atomically)."""
    session_factory = request.app.state.db_session_factory
    async with session_factory() as session, session.begin():
        yield session


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None
