from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.platform.domain.enums import OutboxStatus

MAX_OUTBOX_ATTEMPTS = 5

REDACTED = "[redacted]"


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

    def _redact_payload(self) -> None:
        """Strip the payload's values once the row can no longer be delivered.

        The payload carries the *raw* verification/reset token - it has to, the
        provider needs it to render the link. But `verification_tokens` stores
        only a SHA-256 hash precisely so a database leak yields nothing
        redeemable, and an outbox row retained "through operational/audit
        retention" (database-design.md 21) with the plaintext in it gives that
        guarantee straight back. Keys are kept so the row still shows what was
        sent; only the values go.
        """
        self.payload = dict.fromkeys(self.payload, REDACTED)

    def mark_sent(self, at: datetime) -> None:
        self.status = OutboxStatus.SENT
        self.sent_at = at
        self.updated_at = at
        self._redact_payload()

    def mark_failed(self, error: str, *, next_attempt_at: datetime, at: datetime) -> None:
        self.attempt_count += 1
        self.last_error = error[:1000]
        self.updated_at = at
        if self.attempt_count >= MAX_OUTBOX_ATTEMPTS:
            self.status = OutboxStatus.FAILED
            # Terminal too: nothing retries a failed row and there is no requeue
            # path, so its token is dead weight that only adds exposure.
            self._redact_payload()
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
