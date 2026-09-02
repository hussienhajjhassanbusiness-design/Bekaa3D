from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.domain.entities import AuditLogEntry, EmailOutboxMessage
from app.platform.domain.enums import OutboxStatus
from app.platform.infrastructure.models import AuditLogModel, EmailOutboxModel


def _outbox_to_domain(model: EmailOutboxModel) -> EmailOutboxMessage:
    return EmailOutboxMessage(
        id=model.id,
        user_id=model.user_id,
        recipient_email=str(model.recipient_email),
        template=model.template,
        payload=model.payload,
        status=model.status,
        send_after=model.send_after,
        attempt_count=model.attempt_count,
        last_error=model.last_error,
        sent_at=model.sent_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


class EmailOutboxRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(
        self,
        *,
        user_id: UUID | None,
        recipient_email: str,
        template: str,
        payload: dict[str, Any],
    ) -> EmailOutboxMessage:
        model = EmailOutboxModel(
            user_id=user_id,
            recipient_email=recipient_email,
            template=template,
            payload=payload,
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _outbox_to_domain(model)

    async def claim_due(self, *, limit: int, now: datetime) -> list[EmailOutboxMessage]:
        """Locks up to `limit` due pending rows for this transaction only, so
        concurrent workers never process the same message (SRS: outbox rows must
        not be delivered twice by concurrent workers)."""
        stmt = (
            select(EmailOutboxModel)
            .where(
                EmailOutboxModel.status == OutboxStatus.PENDING,
                EmailOutboxModel.send_after <= now,
            )
            .order_by(EmailOutboxModel.send_after)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        models = (await self._session.scalars(stmt)).all()
        return [_outbox_to_domain(model) for model in models]

    async def save(self, message: EmailOutboxMessage) -> None:
        model = await self._session.get(EmailOutboxModel, message.id)
        if model is None:
            raise ValueError(f"EmailOutboxMessage {message.id} not found")
        model.status = message.status
        # payload is written back because reaching a terminal state redacts it
        model.payload = message.payload
        model.send_after = message.send_after
        model.attempt_count = message.attempt_count
        model.last_error = message.last_error
        model.sent_at = message.sent_at
        await self._session.flush()


class AuditLogRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(
        self,
        *,
        actor_user_id: UUID | None,
        action: str,
        entity_type: str,
        entity_id: UUID | None,
        before_data: dict[str, Any] | None = None,
        after_data: dict[str, Any] | None = None,
        request_id: str | None = None,
        ip_hash: str | None = None,
    ) -> AuditLogEntry:
        model = AuditLogModel(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            before_data=before_data,
            after_data=after_data,
            request_id=request_id,
            ip_hash=ip_hash,
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return AuditLogEntry(
            id=model.id,
            actor_user_id=model.actor_user_id,
            action=model.action,
            entity_type=model.entity_type,
            entity_id=model.entity_id,
            before_data=model.before_data,
            after_data=model.after_data,
            request_id=model.request_id,
            ip_hash=model.ip_hash,
            created_at=model.created_at,
        )
