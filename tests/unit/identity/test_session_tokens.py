from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from app.identity.domain.enums import UserRole
from app.identity.domain.exceptions import InvalidSessionError
from app.identity.infrastructure.session_tokens import (
    decode_access_token,
    decode_refresh_token,
    issue_access_token,
    issue_refresh_token,
)

NOW = datetime.now(UTC)


def _access(**overrides: object) -> str:
    kwargs: dict[str, object] = {
        "user_id": uuid4(),
        "session_id": uuid4(),
        "role": UserRole.CUSTOMER,
        "email_verified": True,
        "now": NOW,
    }
    kwargs.update(overrides)
    return issue_access_token(**kwargs)  # type: ignore[arg-type]


def test_access_token_round_trips_its_claims() -> None:
    user_id, session_id = uuid4(), uuid4()

    token = _access(
        user_id=user_id, session_id=session_id, role=UserRole.ADMIN, email_verified=False
    )
    claims = decode_access_token(token)

    assert claims.user_id == user_id
    assert claims.session_id == session_id
    assert claims.role is UserRole.ADMIN
    assert claims.email_verified is False


def test_refresh_token_round_trips_session_and_version() -> None:
    session_id = uuid4()

    token = issue_refresh_token(
        session_id=session_id,
        token_version=7,
        expires_at=NOW + timedelta(days=30),
        now=NOW,
    )
    claims = decode_refresh_token(token)

    assert claims.session_id == session_id
    assert claims.token_version == 7


def test_an_access_token_cannot_be_used_as_a_refresh_token() -> None:
    """Both are signed with the same key, so only the `typ` claim stops one
    standing in for the other - a 15-minute credential must never be accepted
    where a 30-day one is expected."""
    with pytest.raises(InvalidSessionError):
        decode_refresh_token(_access())


def test_a_refresh_token_cannot_be_used_as_an_access_token() -> None:
    token = issue_refresh_token(
        session_id=uuid4(), token_version=1, expires_at=NOW + timedelta(days=30), now=NOW
    )

    with pytest.raises(InvalidSessionError):
        decode_access_token(token)


def test_expired_access_token_is_rejected() -> None:
    token = _access(now=NOW - timedelta(days=1))

    with pytest.raises(InvalidSessionError):
        decode_access_token(token)


def test_expired_refresh_token_is_rejected() -> None:
    token = issue_refresh_token(
        session_id=uuid4(),
        token_version=1,
        expires_at=NOW - timedelta(seconds=1),
        now=NOW - timedelta(days=1),
    )

    with pytest.raises(InvalidSessionError):
        decode_refresh_token(token)


def test_a_token_signed_with_another_key_is_rejected() -> None:
    forged = jwt.encode(
        {
            "typ": "access",
            "sub": str(uuid4()),
            "sid": str(uuid4()),
            "role": "admin",
            "ver": True,
            "exp": NOW + timedelta(hours=1),
        },
        "not-the-real-signing-key-but-long-enough-to-avoid-a-warning",
        algorithm="HS256",
    )

    with pytest.raises(InvalidSessionError):
        decode_access_token(forged)


def test_an_unsigned_alg_none_token_is_rejected() -> None:
    """decode() is called with an explicit algorithm allowlist, so a token that
    declares `alg: none` and carries no signature cannot be accepted."""
    forged = jwt.encode(
        {"typ": "access", "sub": str(uuid4()), "sid": str(uuid4()), "role": "admin", "ver": True},
        key="",
        algorithm="none",
    )

    with pytest.raises(InvalidSessionError):
        decode_access_token(forged)


@pytest.mark.parametrize("garbage", ["", "not-a-jwt", "a.b.c"])
def test_malformed_tokens_are_rejected(garbage: str) -> None:
    with pytest.raises(InvalidSessionError):
        decode_access_token(garbage)
