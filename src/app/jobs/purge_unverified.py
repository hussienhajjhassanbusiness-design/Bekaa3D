from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.core.config import get_settings
from app.identity.infrastructure.repositories import UserRepository

logger = structlog.get_logger()


async def purge_unverified_accounts(ctx: dict[str, Any]) -> int:
    """arq job: physically removes accounts that were never verified.

    FR-02 lists this under failure behaviour: an address that registers and
    never confirms leaves a row holding an email address indefinitely, which is
    personal data retained for no purpose. Verified accounts are never touched -
    those are anonymised through the account-deletion flow instead
    (database-design.md 5.1).

    The retention period is read from settings today; VS-007 turns it into an
    admin-editable database setting and replaces only this one lookup.
    """
    settings = get_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.unverified_account_retention_days)

    session_factory = ctx["session_factory"]
    async with session_factory() as session, session.begin():
        purged = await UserRepository(session).purge_never_verified_before(cutoff)

    if purged:
        await logger.ainfo(
            "unverified_accounts_purged",
            count=purged,
            retention_days=settings.unverified_account_retention_days,
        )
    return purged
