"""Authentication dependencies.

Identity owns authentication, so other bounded contexts depend on these rather
than decoding cookies themselves - one place decides what "authenticated"
means, and one place decides the error contract for failing it."""

from fastapi import Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.cookies import ACCESS_COOKIE
from app.api.dependencies import get_session
from app.core.exceptions import ApiError
from app.core.security import verify_csrf_token
from app.identity.domain.entities import User
from app.identity.domain.exceptions import InvalidSessionError
from app.identity.infrastructure.repositories import UserRepository
from app.identity.infrastructure.session_tokens import AccessTokenClaims, decode_access_token

CSRF_HEADER = "X-CSRF-Token"


def unauthenticated_error() -> ApiError:
    return ApiError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        code="AUTH_REQUIRED",
        title="Authentication required",
        detail="A valid session is required for this request.",
    )


async def current_claims(request: Request) -> AccessTokenClaims:
    """Read the access-token cookie, or 401.

    Note this trusts the signed token for the length of its 15-minute life and
    does not read the `sessions` row. That is the deliberate trade in ADR-006:
    revocation takes effect at the next refresh rather than instantly, which is
    what keeps ordinary authenticated reads free of a database round-trip."""
    raw = request.cookies.get(ACCESS_COOKIE)
    if not raw:
        raise unauthenticated_error()
    try:
        return decode_access_token(raw)
    except InvalidSessionError as exc:
        raise unauthenticated_error() from exc


async def current_user(
    claims: AccessTokenClaims = Depends(current_claims),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Load the authenticated user's own row, or 401.

    Use this only where the row is needed anyway. `current_claims` deliberately
    avoids the database (ADR-006), so routes that need nothing beyond the token
    should keep depending on it directly rather than paying for this read.

    Because the read happens regardless here, it also re-checks
    `can_authenticate` rather than trusting the token for its full 15 minutes:
    an account disabled, anonymised or deleted a moment ago must not keep being
    served its own personal data until the next refresh."""
    user = await UserRepository(session).get_by_id(claims.user_id)
    if user is None or not user.can_authenticate:
        raise unauthenticated_error()
    return user


async def require_csrf(
    request: Request, claims: AccessTokenClaims = Depends(current_claims)
) -> AccessTokenClaims:
    """Double-submit check for unsafe cookie-authenticated methods (SEC-03)."""
    if not verify_csrf_token(
        session_id=claims.session_id, presented=request.headers.get(CSRF_HEADER)
    ):
        raise ApiError(
            status_code=status.HTTP_403_FORBIDDEN,
            code="CSRF_INVALID",
            title="CSRF token missing or invalid",
            detail=f"Send this session's CSRF cookie value in the {CSRF_HEADER} header.",
        )
    return claims


def user_agent(request: Request) -> str | None:
    # Truncated because it is attacker-controlled free text going into a TEXT
    # column; 512 is far more than any real browser sends.
    value = request.headers.get("User-Agent")
    return value[:512] if value else None
