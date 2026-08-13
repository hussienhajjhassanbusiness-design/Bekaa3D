import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.integrations.email.ports import EmailProviderPort
from app.jobs import outbox as outbox_job
from app.platform.infrastructure.models import EmailOutboxModel
from app.platform.infrastructure.repositories import EmailOutboxRepository


def _unique_email() -> str:
    return f"test-{uuid.uuid4().hex}@example.com"


@pytest.mark.integration
async def test_dispatch_outbox_sends_a_pending_message_and_marks_it_sent(
    db_engine: AsyncEngine,
) -> None:
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async with session_factory() as session, session.begin():
        repo = EmailOutboxRepository(session)
        message = await repo.add(
            user_id=None,
            recipient_email=_unique_email(),
            template="verification_email",
            payload={"token": "abc"},
        )

    processed = await outbox_job.dispatch_outbox({"session_factory": session_factory})
    assert processed >= 1

    async with session_factory() as session:
        row = await session.get(EmailOutboxModel, message.id)
        assert row is not None
        assert row.status == "sent"
        assert row.sent_at is not None


@pytest.mark.integration
async def test_dispatch_outbox_retries_on_provider_failure(
    db_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    class FailingProvider(EmailProviderPort):
        async def send(self, *, to: str, template: str, payload: dict[str, Any]) -> None:
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr(outbox_job, "get_email_provider", lambda settings: FailingProvider())

    async with session_factory() as session, session.begin():
        repo = EmailOutboxRepository(session)
        message = await repo.add(
            user_id=None,
            recipient_email=_unique_email(),
            template="verification_email",
            payload={"token": "abc"},
        )

    await outbox_job.dispatch_outbox({"session_factory": session_factory})

    async with session_factory() as session:
        row = await session.get(EmailOutboxModel, message.id)
        assert row is not None
        assert row.status == "pending"
        assert row.attempt_count == 1
        assert row.last_error is not None
        assert row.send_after > datetime.now(UTC)


@pytest.mark.integration
async def test_dispatch_outbox_marks_message_failed_after_max_attempts(
    db_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    class FailingProvider(EmailProviderPort):
        async def send(self, *, to: str, template: str, payload: dict[str, Any]) -> None:
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr(outbox_job, "get_email_provider", lambda settings: FailingProvider())

    async with session_factory() as session, session.begin():
        repo = EmailOutboxRepository(session)
        message = await repo.add(
            user_id=None,
            recipient_email=_unique_email(),
            template="verification_email",
            payload={"token": "abc"},
        )

    for _ in range(5):
        async with session_factory() as session, session.begin():
            row = await session.get(EmailOutboxModel, message.id)
            assert row is not None
            row.send_after = datetime.now(UTC)  # force it due immediately for the next claim
        await outbox_job.dispatch_outbox({"session_factory": session_factory})

    async with session_factory() as session:
        row = await session.get(EmailOutboxModel, message.id)
        assert row is not None
        assert row.status == "failed"
        assert row.attempt_count == 5
