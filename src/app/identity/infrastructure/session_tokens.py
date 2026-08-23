"""Minting and reading the two signed cookies that carry a login session.

Neither token is a source of truth on its own. The access token is trusted for
its short lifetime; the refresh token only says *which* session and version is
being claimed - the `sessions` row decides whether that claim is still valid."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import jwt

from app.core.config import get_settings
from app.identity.domain.enums import UserRole
from app.identity.domain.exceptions import InvalidSessionError

# Pinned explicitly and passed to decode() as a single-element allowlist. Never
# read the algorithm from the token itself - that is the classic "alg: none"
# forgery, where an attacker strips the signature and the library obliges.
_ALGORITHM = "HS256"

_ACCESS_TYPE = "access"
_REFRESH_TYPE = "refresh"


@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: UUID
    session_id: UUID
    role: UserRole
    email_verified: bool


@dataclass(frozen=True)
class RefreshTokenClaims:
    session_id: UUID
    token_version: int


def issue_access_token(
    *,
    user_id: UUID,
    session_id: UUID,
    role: UserRole,
    email_verified: bool,
    now: datetime,
) -> str:
    settings = get_settings()
    payload = {
        "typ": _ACCESS_TYPE,
        "sub": str(user_id),
        "sid": str(session_id),
        "role": role.value,
        "ver": email_verified,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_signing_key, algorithm=_ALGORITHM)


def issue_refresh_token(
    *, session_id: UUID, token_version: int, expires_at: datetime, now: datetime
) -> str:
    """`exp` matches the session row's deadline exactly, so a rotated token
    never outlives the session it belongs to."""
    settings = get_settings()
    payload = {
        "typ": _REFRESH_TYPE,
        "sid": str(session_id),
        "tv": token_version,
        "iat": now,
        "exp": expires_at,
    }
    return jwt.encode(payload, settings.jwt_signing_key, algorithm=_ALGORITHM)


def _decode(token: str, *, expected_type: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload: dict[str, Any] = jwt.decode(
            token, settings.jwt_signing_key, algorithms=[_ALGORITHM]
        )
    except jwt.InvalidTokenError as exc:
        # Covers bad signature, expiry, malformed input - all of which mean the
        # same thing to the caller: this credential cannot be trusted.
        raise InvalidSessionError() from exc

    # Without this check an access token could be replayed as a refresh token
    # (or vice versa), since both are signed with the same key.
    if payload.get("typ") != expected_type:
        raise InvalidSessionError()
    return payload


def decode_access_token(token: str) -> AccessTokenClaims:
    payload = _decode(token, expected_type=_ACCESS_TYPE)
    try:
        return AccessTokenClaims(
            user_id=UUID(payload["sub"]),
            session_id=UUID(payload["sid"]),
            role=UserRole(payload["role"]),
            email_verified=bool(payload["ver"]),
        )
    except (KeyError, ValueError) as exc:
        raise InvalidSessionError() from exc


def decode_refresh_token(token: str) -> RefreshTokenClaims:
    payload = _decode(token, expected_type=_REFRESH_TYPE)
    try:
        return RefreshTokenClaims(session_id=UUID(payload["sid"]), token_version=int(payload["tv"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidSessionError() from exc
