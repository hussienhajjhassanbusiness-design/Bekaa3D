from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import client_ip, get_session
from app.core.exceptions import ApiError
from app.core.rate_limit import rate_limiter
from app.core.security import hash_ip
from app.identity.api.schemas import (
    RegisterRequest,
    RegistrationAccepted,
    ResendVerificationRequest,
    VerifyEmailRequest,
)
from app.identity.application.commands.register_user import RegisterUser
from app.identity.application.commands.resend_verification import ResendVerification
from app.identity.application.commands.verify_email import VerifyEmail
from app.identity.domain.exceptions import (
    AlreadyVerifiedError,
    InvalidVerificationTokenError,
    VerificationTokenExpiredError,
)
from app.identity.infrastructure.repositories import UserRepository, VerificationTokenRepository
from app.platform.infrastructure.repositories import AuditLogRepository, EmailOutboxRepository

router = APIRouter(prefix="/auth", tags=["auth"])

# V1 design assumptions (SRS §30.3): generous enough for real retries, tight
# enough to blunt automated abuse. verify-email is looser since its token is
# effectively unguessable (32 random bytes), so the endpoint mainly needs
# protection against accidental retry storms, not brute force.
_REGISTER_LIMIT = rate_limiter(key_prefix="auth:register", limit=5, window_seconds=3600)
_RESEND_LIMIT = rate_limiter(key_prefix="auth:resend", limit=5, window_seconds=3600)
_VERIFY_LIMIT = rate_limiter(key_prefix="auth:verify", limit=20, window_seconds=3600)


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
    "/resend-verification",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=RegistrationAccepted,
    dependencies=[Depends(_RESEND_LIMIT)],
)
async def resend_verification(
    body: ResendVerificationRequest,
    session: AsyncSession = Depends(get_session),
) -> RegistrationAccepted:
    use_case = ResendVerification(
        user_repo=UserRepository(session),
        token_repo=VerificationTokenRepository(session),
        outbox_repo=EmailOutboxRepository(session),
    )
    await use_case.execute(email=body.email)
    return RegistrationAccepted()
