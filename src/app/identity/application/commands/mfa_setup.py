from dataclasses import dataclass
from uuid import UUID

from app.core.config import get_settings
from app.identity.domain.enums import MfaMethod
from app.identity.domain.exceptions import (
    InvalidCredentialsError,
    MfaAlreadyEnabledError,
    MfaNotEnrolledError,
)
from app.identity.infrastructure.password_hasher import verify_password
from app.identity.infrastructure.repositories import MfaCredentialRepository, UserRepository
from app.identity.infrastructure.secret_cipher import encrypt_secret
from app.identity.infrastructure.totp import generate_secret, provisioning_uri
from app.platform.infrastructure.repositories import AuditLogRepository


@dataclass(frozen=True)
class MfaSetupResult:
    """Setup material, returned exactly once.

    `secret` and `otpauth_uri` both carry the raw TOTP secret. They exist only
    in this object and the response built from it - never in a log line, never
    in an audit row, never readable back from the database."""

    secret: str
    otpauth_uri: str
    issuer: str
    account_name: str


class MfaSetup:
    """Begin TOTP enrollment for an administrator.

    Deliberately does not enable anything. A secret is generated and stored
    encrypted with `enabled_at` left NULL, so an enrollment that is started and
    abandoned leaves the account exactly as it was (database-design.md 5.6)."""

    def __init__(
        self,
        user_repo: UserRepository,
        credential_repo: MfaCredentialRepository,
        audit_repo: AuditLogRepository,
    ) -> None:
        self._users = user_repo
        self._credentials = credential_repo
        self._audit = audit_repo

    async def execute(
        self,
        *,
        user_id: UUID,
        current_password: str,
        request_id: str | None,
        ip_hash: str | None,
    ) -> MfaSetupResult:
        user = await self._users.get_by_id(user_id)
        if user is None or not user.can_authenticate:
            raise MfaNotEnrolledError()

        # Re-authenticate even though the caller already holds a valid session.
        # Enrollment decides what the second factor *is*, so a borrowed or
        # hijacked session must not be enough to point it at an attacker's app.
        if not verify_password(password=current_password, password_hash=user.password_hash):
            raise InvalidCredentialsError()

        existing = await self._credentials.get_by_user_id(user_id)
        if existing is not None and existing.is_enabled:
            raise MfaAlreadyEnabledError()

        secret = generate_secret()
        ciphertext = encrypt_secret(secret)

        if existing is None:
            await self._credentials.add(
                user_id=user_id, method=MfaMethod.TOTP, secret_ciphertext=ciphertext
            )
        else:
            # Restarting an unconfirmed enrollment: replace the pending secret.
            # Safe precisely because nothing is enabled yet.
            existing.secret_ciphertext = ciphertext
            await self._credentials.save(existing)

        await self._audit.add(
            actor_user_id=user_id,
            action="mfa.enrollment_started",
            entity_type="MfaCredential",
            entity_id=None,
            request_id=request_id,
            ip_hash=ip_hash,
        )

        return MfaSetupResult(
            secret=secret,
            otpauth_uri=provisioning_uri(secret=secret, account_name=user.email),
            issuer=get_settings().mfa_issuer,
            account_name=user.email,
        )
