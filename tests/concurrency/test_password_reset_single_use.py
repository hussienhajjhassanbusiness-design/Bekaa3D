import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.identity.application.commands.confirm_password_reset import ConfirmPasswordReset
from app.identity.domain.exceptions import InvalidPasswordResetTokenError
from app.identity.infrastructure.models import PasswordResetTokenModel
from app.identity.infrastructure.password_hasher import verify_password
from app.identity.infrastructure.repositories import (
    PasswordResetTokenRepository,
    SessionRepository,
    UserRepository,
)
from app.identity.infrastructure.token_service import generate_raw_token, hash_token
from app.platform.infrastructure.repositories import AuditLogRepository

WINNING_PASSWORD = "the-one-that-should-stick"
LOSING_PASSWORD = "the-one-that-should-not"


async def _seed_reset_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> tuple[uuid.UUID, str]:
    raw_token = generate_raw_token()
    async with session_factory() as db, db.begin():
        user = await UserRepository(db).add(
            email=f"test-{uuid.uuid4().hex}@example.com", password_hash="not-a-real-hash"
        )
        await PasswordResetTokenRepository(db).add(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    return user.id, raw_token


async def _confirm_once(
    session_factory: async_sessionmaker[AsyncSession], raw_token: str, new_password: str
) -> None:
    """One request's worth of work, transaction boundary included - the same
    shape get_session gives the real route."""
    async with session_factory() as db, db.begin():
        use_case = ConfirmPasswordReset(
            user_repo=UserRepository(db),
            token_repo=PasswordResetTokenRepository(db),
            session_repo=SessionRepository(db),
            audit_repo=AuditLogRepository(db),
        )
        await use_case.execute(
            raw_token=raw_token, new_password=new_password, request_id=None, ip_hash=None
        )


@pytest.mark.integration
@pytest.mark.concurrency
async def test_one_reset_token_submitted_twice_at_once_is_redeemed_once(
    db_engine: AsyncEngine,
) -> None:
    """Single-use has to hold under concurrency, not just in sequence.

    Without SELECT ... FOR UPDATE in get_by_hash_for_update, both transactions
    would read the same unused row, both would pass the `used_at IS NULL` check,
    and both would write a password - so whichever committed last would decide
    the account's credential. An attacker racing the real user for a token they
    both hold would win roughly half the time."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    user_id, raw_token = await _seed_reset_token(session_factory)

    outcomes = await asyncio.gather(
        _confirm_once(session_factory, raw_token, WINNING_PASSWORD),
        _confirm_once(session_factory, raw_token, LOSING_PASSWORD),
        return_exceptions=True,
    )

    successes = [o for o in outcomes if o is None]
    rejections = [o for o in outcomes if isinstance(o, InvalidPasswordResetTokenError)]
    assert len(successes) == 1, outcomes
    assert len(rejections) == 1, outcomes

    async with session_factory() as db:
        user = await UserRepository(db).get_by_id(user_id)
        rows = list(
            await db.scalars(
                select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user_id)
            )
        )

    assert user is not None
    # Exactly one of the two passwords is in force, and the loser's is not.
    assert not verify_password(password=LOSING_PASSWORD, password_hash=user.password_hash)
    assert verify_password(password=WINNING_PASSWORD, password_hash=user.password_hash)
    assert len(rows) == 1
    assert rows[0].used_at is not None


@pytest.mark.integration
@pytest.mark.concurrency
async def test_resets_for_different_accounts_do_not_block_each_other(
    db_engine: AsyncEngine,
) -> None:
    """The lock must be per-token. If it serialised all resets, unrelated users
    would queue behind each other."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    _, first_token = await _seed_reset_token(session_factory)
    _, second_token = await _seed_reset_token(session_factory)

    outcomes = await asyncio.gather(
        _confirm_once(session_factory, first_token, WINNING_PASSWORD),
        _confirm_once(session_factory, second_token, WINNING_PASSWORD),
        return_exceptions=True,
    )

    assert all(o is None for o in outcomes), outcomes
