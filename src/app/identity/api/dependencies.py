"""Authentication dependencies.

Identity owns authentication, so other bounded contexts depend on these rather
than decoding cookies themselves - one place decides what "authenticated"
means, and one place decides the error contract for failing it."""

from fastapi import Depends, Request, status

from app.api.cookies import ACCESS_COOKIE
from app.core.exceptions import ApiError
from app.core.security import verify_csrf_token
from app.identity.domain.enums import UserRole
from app.identity.domain.exceptions import InvalidSessionError
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


def not_found_error() -> ApiError:
    """The 404 an authenticated non-administrator gets from an admin route.

    SEC-10 requires 404 rather than 403: a 403 confirms the route exists, which
    tells an ordinary customer exactly which admin surface to go looking for.

    `title` and `detail` deliberately reproduce, byte for byte, what Starlette's
    own 404 handler emits for a path that matches no route at all (see
    `_STATUS_CODE_NAMES` in api/errors.py). Matching only the status and the
    code is not enough - a difference in the wording is just as good an oracle,
    and test_a_customer_cannot_distinguish_a_real_admin_route_from_a_missing_one
    is what holds these two in agreement."""
    return ApiError(
        status_code=status.HTTP_404_NOT_FOUND,
        code="NOT_FOUND",
        title="Request cannot be completed",
        detail="Not Found",
    )


async def require_admin(claims: AccessTokenClaims = Depends(current_claims)) -> AccessTokenClaims:
    """The admin boundary: authenticated, administrator, MFA complete.

    The three failures are deliberately different, in this order:

    - no session at all      -> 401 AUTH_REQUIRED (from current_claims)
    - authenticated customer -> 404 NOT_FOUND     (SEC-10 information hiding)
    - admin without MFA      -> 401 MFA_REQUIRED  (SEC-04, api-endpoints.md:105)

    No challenge is opened here. Under the login-gated flow the only way to get
    a challenge is `POST /auth/login` (api-endpoints.md:252), so an
    administrator who reaches this branch is in one of two states, and neither
    is fixed by a step-up:

    - they have not finished enrolling, and need `/auth/mfa/setup` +
      `/setup/confirm`, which this very session is already entitled to call;
    - they hold a session predating the moment MFA was enabled on the account,
      and need to log in again to be challenged.

    Minting a challenge here would be a second, session-bound way to reach an
    MFA-complete session - exactly the parallel authentication path the slice
    is meant not to have.

    MFA state is read from the signed token rather than from Redis, keeping
    ADR-006's "no database round-trip on an ordinary authenticated request"
    property. A session created through `/auth/mfa/verify` is born with the
    claim set, and refresh carries it across rotation, so the claim cannot lag
    the session's real state."""
    if claims.role is not UserRole.ADMIN:
        raise not_found_error()

    if not claims.mfa_completed:
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="MFA_REQUIRED",
            title="Second factor required",
            detail="This session has not completed MFA. Sign in again to be challenged.",
        )

    return claims
