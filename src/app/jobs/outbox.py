from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.core.config import get_settings
from app.integrations.email.factory import get_email_provider
from app.platform.domain.enums import OutboxStatus
from app.platform.infrastructure.repositories import EmailOutboxRepository

logger = structlog.get_logger()

BATCH_SIZE = 20
RETRY_BASE_SECONDS = 60


async def dispatch_outbox(ctx: dict[str, Any]) -> int:
    """arq job: sends due, pending outbox emails. Scheduled every minute (SRS §23).
    Concurrency safety comes from the repository's SELECT ... FOR UPDATE SKIP
    LOCKED claim, not from anything in this function."""
    session_factory = ctx["session_factory"]
    provider = get_email_provider(get_settings())

    async with session_factory() as session, session.begin():
        repo = EmailOutboxRepository(session)
        messages = await repo.claim_due(limit=BATCH_SIZE, now=datetime.now(UTC))

        for message in messages:
            try:
                await provider.send(
                    to=message.recipient_email,
                    template=message.template,
                    payload=message.payload,
                )
            except Exception as exc:
                next_attempt = datetime.now(UTC) + timedelta(
                    seconds=RETRY_BASE_SECONDS * (2**message.attempt_count)
                )
                message.mark_failed(str(exc), next_attempt_at=next_attempt, at=datetime.now(UTC))
                if message.status == OutboxStatus.FAILED:
                    await logger.aerror(
                        "outbox_message_permanently_failed",
                        outbox_id=str(message.id),
                        attempts=message.attempt_count,
                    )
                else:
                    await logger.awarning(
                        "outbox_send_failed",
                        outbox_id=str(message.id),
                        attempt=message.attempt_count,
                        error=str(exc),
                    )
            else:
                message.mark_sent(datetime.now(UTC))
            await repo.save(message)

        return len(messages)
