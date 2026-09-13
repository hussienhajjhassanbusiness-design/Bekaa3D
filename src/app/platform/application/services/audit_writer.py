"""Writing audit records from other bounded contexts.

Platform owns `audit_logs`. Other contexts must not reach into its
infrastructure to write there - cross-context access goes through a service
interface, which is what keeps this a modular monolith rather than a shared
database (CLAUDE.md, architecture rules). This is the write-side counterpart to
`SettingsReader`, and the same shape Engagement's `create_notification` uses.

The writer takes the caller's `AsyncSession` rather than opening its own, and
**never commits**. That is the whole point: BR-132 requires a business mutation
and its audit record to land together, which is only achievable if both run in
one transaction owned by the caller. A writer that committed on its own could
leave an audit row describing a change that was still able to fail.

Introduced by VS-010. Existing audit call sites inside Platform itself continue
to use `AuditLogRepository` directly - that is Platform writing to its own
table, which is not a cross-context dependency and is deliberately left alone.
"""

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.infrastructure.repositories import AuditLogRepository


class AuditWriter:
    """The sanctioned way for another context to append an audit record."""

    def __init__(self, session: AsyncSession) -> None:
        self._audit = AuditLogRepository(session)

    async def record(
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
    ) -> None:
        """Append one audit row inside the caller's transaction.

        Returns nothing: callers need the record written, not the row back, and
        handing out the persisted entity would invite another context to start
        depending on Platform's `AuditLogEntry` shape.
        """
        await self._audit.add(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            before_data=before_data,
            after_data=after_data,
            request_id=request_id,
            ip_hash=ip_hash,
        )
