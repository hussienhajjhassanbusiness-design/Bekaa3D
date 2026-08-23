from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.core.config import get_settings
from app.core.security import csrf_token_for_session
from app.identity.application.services.login_throttle import LoginThrottle
from app.identity.domain.enums import UserRole
from app.identity.domain.exceptions import AccountDisabledError, InvalidCredentialsError
from app.identity.infrastructure.password_hasher import hash_password, verify_password
from app.identity.infrastructure.repositories import SessionRepository, UserRepository
from app.identity.infrastructure.session_tokens import issue_access_token, issue_refresh_token
from app.identity.infrastructure.token_service import hash_token
from app.platform.infrastructure.repositories import AuditLogRepository

# Argon2 verification is deliberately slow, so skipping it for an unknown email
# would make "no such account" measurably faster to answer than "wrong
# password" - an attacker can time that difference and enumerate addresses.
# Verifying against this throwaway hash keeps both paths equally slow.
_DUMMY_PASSWORD_HASH = hash_password("timing-equalisation-placeholder")


@dataclass(frozen=True)
class LoginResult:
    user_id: UUID
    email: str
    session_id: UUID
    session_expires_at: datetime
    role: UserRole
    email_verified: bool
    access_token: str
    refresh_token: str
    csrf_token: str


class Login:
    def __init__(
        self,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        audit_repo: AuditLogRepository,
        throttle: LoginThrottle,
    ) -> None:
        self._users = user_repo
        self._sessions = session_repo
        self._audit = audit_repo
        self._throttle = throttle

    async def execute(
        self,
        *,
        email: str,
        password: str,
        ip: str | None,
        ip_hash: str | None,
        user_agent: str | None,
        request_id: str | None,
    ) -> LoginResult:
        await self._throttle.check(email=email, ip=ip)

        user = await self._users.get_by_email(email)
        if user is None:
            verify_password(password=password, password_hash=_DUMMY_PASSWORD_HASH)
            await self._throttle.record_failure(email=email, ip=ip)
            raise InvalidCredentialsError()

        if not verify_password(password=password, password_hash=user.password_hash):
            await self._throttle.record_failure(email=email, ip=ip)
            raise InvalidCredentialsError()

        # Only now, after the password has proven the caller owns this account,
        # is it safe to be specific about why login is refused. Doing this check
        # before verification would let anyone probe which addresses are
        # suspended (FR-02: errors must not reveal whether an email exists).
        if not user.can_authenticate:
            raise AccountDisabledError(user.id)

        await self._throttle.reset(email=email, ip=ip)

        settings = get_settings()
        now = datetime.now(UTC)
        session_id = uuid4()
        expires_at = now + timedelta(days=settings.refresh_token_days)

        refresh_token = issue_refresh_token(
            session_id=session_id, token_version=1, expires_at=expires_at, now=now
        )
        await self._sessions.add(
            session_id=session_id,
            user_id=user.id,
            refresh_token_hash=hash_token(refresh_token),
            expires_at=expires_at,
            ip_hash=ip_hash,
            user_agent=user_agent,
        )
        await self._audit.add(
            actor_user_id=user.id,
            action="user.logged_in",
            entity_type="Session",
            entity_id=session_id,
            request_id=request_id,
            ip_hash=ip_hash,
        )

        return LoginResult(
            user_id=user.id,
            email=user.email,
            session_id=session_id,
            session_expires_at=expires_at,
            role=user.role,
            email_verified=user.is_verified,
            access_token=issue_access_token(
                user_id=user.id,
                session_id=session_id,
                role=user.role,
                email_verified=user.is_verified,
                now=now,
            ),
            refresh_token=refresh_token,
            csrf_token=csrf_token_for_session(session_id),
        )
