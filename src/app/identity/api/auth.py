from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.cookies import REFRESH_COOKIE, clear_session_cookies, set_session_cookies
from app.api.dependencies import client_ip, get_session
from app.core.exceptions import ApiError
from app.core.rate_limit import rate_limiter
from app.core.security import hash_ip, verify_csrf_token
from app.identity.api.dependencies import (
    CSRF_HEADER,
    require_csrf,
    unauthenticated_error,
    user_agent,
)
from app.identity.api.schemas import (
    LoginRequest,
    PasswordResetAccepted,
    PasswordResetConfirm,
    PasswordResetRequest,
    RegisterRequest,
    RegistrationAccepted,
    ResendVerificationRequest,
    SessionRead,
    VerifyEmailRequest,
)
from app.identity.application.commands.confirm_password_reset import ConfirmPasswordReset
from app.identity.application.commands.login import Login
from app.identity.application.commands.logout import Logout
from app.identity.application.commands.refresh_session import RefreshSession
from app.identity.application.commands.register_user import RegisterUser
from app.identity.application.commands.request_password_reset import RequestPasswordReset
from app.identity.application.commands.resend_verification import ResendVerification
from app.identity.application.commands.verify_email import VerifyEmail
from app.identity.application.services.login_throttle import LoginThrottle
from app.identity.domain.exceptions import (
    AccountDisabledError,
    AccountLockedError,
    AlreadyVerifiedError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvalidSessionError,
    InvalidVerificationTokenError,
    PasswordResetTokenExpiredError,
    SessionTerminatedError,
    VerificationTokenExpiredError,
)
from app.identity.infrastructure.repositories import (
    PasswordResetTokenRepository,
    SessionRepository,
    UserRepository,
    VerificationTokenRepository,
)
from app.identity.infrastructure.session_tokens import AccessTokenClaims, decode_refresh_token
from app.platform.infrastructure.repositories import AuditLogRepository, EmailOutboxRepository

router = APIRouter(prefix="/auth", tags=["auth"])

# V1 design assumptions (SRS §30.3): generous enough for real retries, tight
# enough to blunt automated abuse. verify-email is looser since its token is
# effectively unguessable (32 random bytes), so the endpoint mainly needs
# protection against accidental retry storms, not brute force.
_REGISTER_LIMIT = rate_limiter(key_prefix="auth:register", limit=5, window_seconds=3600)
_RESEND_LIMIT = rate_limiter(key_prefix="auth:resend", limit=5, window_seconds=3600)
_VERIFY_LIMIT = rate_limiter(key_prefix="auth:verify", limit=20, window_seconds=3600)
# A coarse per-IP net in front of the per-(email, IP) lockout in LoginThrottle:
# the throttle stops one account being ground down, this caps total volume from
# one source. Refresh is looser because an active session legitimately rotates
# roughly every 15 minutes, and one IP may carry several of them.
_LOGIN_LIMIT = rate_limiter(key_prefix="auth:login", limit=20, window_seconds=3600)
_REFRESH_LIMIT = rate_limiter(key_prefix="auth:refresh", limit=60, window_seconds=3600)
# Reset request matches resend-verification: both send mail to an address the
# caller has not proved they own. Confirm matches verify-email: its token is 32
# random bytes, so the limit is about retry storms, not guessing.
_RESET_REQUEST_LIMIT = rate_limiter(key_prefix="auth:reset-request", limit=5, window_seconds=3600)
_RESET_CONFIRM_LIMIT = rate_limiter(key_prefix="auth:reset-confirm", limit=20, window_seconds=3600)


@router.post(
    "/register",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=RegistrationAccepted,
    dependencies=[Depends(_REGISTER_LIMIT)],
)
async def register(
    body: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RegistrationAccepted:
    use_case = RegisterUser(
        user_repo=UserRepository(session),
        token_repo=VerificationTokenRepository(session),
        outbox_repo=EmailOutboxRepository(session),
        audit_repo=AuditLogRepository(session),
    )
    ip = client_ip(request)
    await use_case.execute(
        email=body.email,
        password=body.password,
        request_id=getattr(request.state, "request_id", None),
        ip_hash=hash_ip(ip) if ip else None,
    )
    return RegistrationAccepted()


@router.post(
    "/verify-email", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(_VERIFY_LIMIT)]
)
async def verify_email(
    body: VerifyEmailRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> None:
    use_case = VerifyEmail(
        user_repo=UserRepository(session),
        token_repo=VerificationTokenRepository(session),
        audit_repo=AuditLogRepository(session),
    )
    ip = client_ip(request)
    try:
        await use_case.execute(
            raw_token=body.token,
            request_id=getattr(request.state, "request_id", None),
            ip_hash=hash_ip(ip) if ip else None,
        )
    except VerificationTokenExpiredError as exc:
        raise ApiError(
            status_code=status.HTTP_410_GONE,
            code="RESOURCE_EXPIRED",
            title="Verification link expired",
            detail="This verification link has expired. Request a new one.",
        ) from exc
    except (InvalidVerificationTokenError, AlreadyVerifiedError) as exc:
        raise ApiError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_TOKEN",
            title="Verification link invalid",
            detail="This verification link is invalid or has already been used.",
        ) from exc


@router.post(
    "/login",
    response_model=SessionRead,
    dependencies=[Depends(_LOGIN_LIMIT)],
)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    agent: str | None = Depends(user_agent),
    session: AsyncSession = Depends(get_session),
) -> SessionRead:
    use_case = Login(
        user_repo=UserRepository(session),
        session_repo=SessionRepository(session),
        audit_repo=AuditLogRepository(session),
        throttle=LoginThrottle(request.app.state.redis),
    )
    ip = client_ip(request)
    try:
        result = await use_case.execute(
            email=body.email,
            password=body.password,
            ip=ip,
            ip_hash=hash_ip(ip) if ip else None,
            user_agent=agent,
            request_id=getattr(request.state, "request_id", None),
        )
    except AccountLockedError as exc:
        raise ApiError(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="RATE_LIMITED",
            title="Too many failed attempts",
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except InvalidCredentialsError as exc:
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_CREDENTIALS",
            title="Login failed",
            detail="Email or password is incorrect.",
        ) from exc
    except AccountDisabledError as exc:
        raise ApiError(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_DISABLED",
            title="Account unavailable",
            detail="This account can no longer be used to sign in.",
        ) from exc

    set_session_cookies(
        response,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        csrf_token=result.csrf_token,
    )
    return SessionRead(
        user_id=result.user_id,
        email=result.email,
        role=result.role,
        email_verified=result.email_verified,
        session_expires_at=result.session_expires_at,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    claims: AccessTokenClaims = Depends(require_csrf),
    session: AsyncSession = Depends(get_session),
) -> None:
    use_case = Logout(
        session_repo=SessionRepository(session), audit_repo=AuditLogRepository(session)
    )
    ip = client_ip(request)
    await use_case.execute(
        session_id=claims.session_id,
        request_id=getattr(request.state, "request_id", None),
        ip_hash=hash_ip(ip) if ip else None,
    )
    clear_session_cookies(response)


@router.post(
    "/refresh",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_REFRESH_LIMIT)],
)
async def refresh(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> None:
    raw_refresh_token = request.cookies.get(REFRESH_COOKIE)
    if not raw_refresh_token:
        raise unauthenticated_error()

    # CSRF is checked against the *refresh* token's session, not the access
    # token's: the whole reason to call refresh is that the access token has
    # expired, so requiring a live one here would make refresh unreachable.
    try:
        claims = decode_refresh_token(raw_refresh_token)
    except InvalidSessionError as exc:
        raise unauthenticated_error() from exc
    if not verify_csrf_token(
        session_id=claims.session_id, presented=request.headers.get(CSRF_HEADER)
    ):
        raise ApiError(
            status_code=status.HTTP_403_FORBIDDEN,
            code="CSRF_INVALID",
            title="CSRF token missing or invalid",
            detail=f"Send this session's CSRF cookie value in the {CSRF_HEADER} header.",
        )

    use_case = RefreshSession(
        user_repo=UserRepository(session),
        session_repo=SessionRepository(session),
        audit_repo=AuditLogRepository(session),
    )
    ip = client_ip(request)
    try:
        result = await use_case.execute(
            raw_refresh_token=raw_refresh_token,
            request_id=getattr(request.state, "request_id", None),
            ip_hash=hash_ip(ip) if ip else None,
        )
    except SessionTerminatedError as exc:
        # The request must fail, but its writes must survive. get_session wraps
        # every request in a transaction that rolls back on exception, which
        # would undo the revocation and the audit row and leave a compromised
        # session alive - so commit the security response before raising.
        await session.commit()
        raise unauthenticated_error() from exc
    except InvalidSessionError as exc:
        raise unauthenticated_error() from exc

    set_session_cookies(
        response,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        csrf_token=result.csrf_token,
    )


@router.post(
    "/resend-verification",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=RegistrationAccepted,
    dependencies=[Depends(_RESEND_LIMIT)],
)
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RegistrationAccepted:
    use_case = ResendVerification(
        user_repo=UserRepository(session),
        token_repo=VerificationTokenRepository(session),
        outbox_repo=EmailOutboxRepository(session),
        audit_repo=AuditLogRepository(session),
    )
    ip = client_ip(request)
    await use_case.execute(
        email=body.email,
        request_id=getattr(request.state, "request_id", None),
        ip_hash=hash_ip(ip) if ip else None,
    )
    return RegistrationAccepted()


@router.post(
    "/password-reset/request",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=PasswordResetAccepted,
    dependencies=[Depends(_RESET_REQUEST_LIMIT)],
)
async def request_password_reset(
    body: PasswordResetRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> PasswordResetAccepted:
    use_case = RequestPasswordReset(
        user_repo=UserRepository(session),
        token_repo=PasswordResetTokenRepository(session),
        outbox_repo=EmailOutboxRepository(session),
        audit_repo=AuditLogRepository(session),
    )
    ip = client_ip(request)
    await use_case.execute(
        email=body.email,
        request_id=getattr(request.state, "request_id", None),
        ip_hash=hash_ip(ip) if ip else None,
    )
    # Unconditional, and there is no error branch above it on purpose: the
    # 202 must be identical for a known address, an unknown one, and one still
    # inside its cooldown (api-endpoints.md §5).
    return PasswordResetAccepted()


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_RESET_CONFIRM_LIMIT)],
)
async def confirm_password_reset(
    body: PasswordResetConfirm,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> None:
    use_case = ConfirmPasswordReset(
        user_repo=UserRepository(session),
        token_repo=PasswordResetTokenRepository(session),
        session_repo=SessionRepository(session),
        audit_repo=AuditLogRepository(session),
    )
    ip = client_ip(request)
    try:
        await use_case.execute(
            raw_token=body.token,
            new_password=body.new_password,
            request_id=getattr(request.state, "request_id", None),
            ip_hash=hash_ip(ip) if ip else None,
        )
    except PasswordResetTokenExpiredError as exc:
        raise ApiError(
            status_code=status.HTTP_410_GONE,
            code="RESOURCE_EXPIRED",
            title="Reset link expired",
            detail="This password reset link has expired. Request a new one.",
        ) from exc
    except InvalidPasswordResetTokenError as exc:
        raise ApiError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_TOKEN",
            title="Reset link invalid",
            detail="This password reset link is invalid or has already been used.",
        ) from exc

    # The use case revoked every session server-side; this clears the now-dead
    # cookies from whichever browser made the call. Harmless when the caller was
    # not logged in, and it stops a browser from carrying credentials that will
    # only fail on the next request.
    clear_session_cookies(response)
