from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.platform.domain.enums import OutboxStatus

MAX_OUTBOX_ATTEMPTS = 5


@dataclass
class EmailOutboxMessage:
    id: UUID
    user_id: UUID | None
    recipient_email: str
    template: str
    payload: dict[str, Any]
    status: OutboxStatus
    send_after: datetime
    attempt_count: int
    last_error: str | None
    sent_at: datetime | None
    created_at: datetime
    updated_at: datetime

    def mark_sent(self, at: datetime) -> None:
        self.status = OutboxStatus.SENT
        self.sent_at = at
        self.updated_at = at

    def mark_failed(self, error: str, *, next_attempt_at: datetime, at: datetime) -> None:
        self.attempt_count += 1
        self.last_error = error[:1000]
        self.updated_at = at
        if self.attempt_count >= MAX_OUTBOX_ATTEMPTS:
            self.status = OutboxStatus.FAILED
        else:
            self.status = OutboxStatus.PENDING
            self.send_after = next_attempt_at


@dataclass
class AuditLogEntry:
    id: UUID
    actor_user_id: UUID | None
    action: str
    entity_type: str
    entity_id: UUID | None
    before_data: dict[str, Any] | None
    after_data: dict[str, Any] | None
    request_id: str | None
    ip_hash: str | None
    created_at: datetime
