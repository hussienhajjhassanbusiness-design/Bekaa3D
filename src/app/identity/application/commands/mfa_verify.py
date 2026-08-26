from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.identity.domain.exceptions import (
    InvalidMfaCodeError,
    InvalidRecoveryCodeError,
    MfaNotEnrolledError,
)
from app.identity.domain.recovery_codes import normalize_code
from app.identity.infrastructure.repositories import (
    MfaCredentialRepository,
    MfaRecoveryCodeRepository,
)
from app.identity.infrastructure.secret_cipher import decrypt_secret
from app.identity.infrastructure.token_service import hash_token
from app.identity.infrastructure.totp import verify_code
from app.platform.infrastructure.repositories import AuditLogRepository


@dataclass(frozen=True)
class MfaVerifyResult:
    used_recovery_code: bool
    remaining_recovery_codes: int


class VerifyMfa:
    """Complete the admin second factor for an already-authenticated session.

    This is a step-up, not a login: the caller already holds a valid session,
    and what happens here is that the session becomes MFA-complete. Marking the
    session and re-issuing its access token is the route's job - this command
    decides only whether the factor was proven."""

    def __init__(
        self,
        credential_repo: MfaCredentialRepository,
        recovery_repo: MfaRecoveryCodeRepository,
        audit_repo: AuditLogRepository,
    ) -> None:
        self._credentials = credential_repo
        self._recovery = recovery_repo
        self._audit = audit_repo

    async def execute(
        self,
        *,
        user_id: UUID,
        code: str | None,
        recovery_code: str | None,
        request_id: str | None,
        ip_hash: str | None,
    ) -> MfaVerifyResult:
        credential = await self._credentials.get_by_user_id(user_id)
        if credential is None or not credential.is_enabled:
            raise MfaNotEnrolledError()

        now = datetime.now(UTC)

        if recovery_code is not None:
            # FOR UPDATE inside the repository: two requests racing the same
            # code serialise there, so exactly one redemption can win.
            stored = await self._recovery.get_unused_by_hash(
                mfa_credential_id=credential.id,
                code_hash=hash_token(normalize_code(recovery_code)),
            )
            if stored is None:
                raise InvalidRecoveryCodeError()
            stored.redeem(now)
            await self._recovery.save(stored)
            remaining = await self._recovery.count_unused(credential.id)

            # Recovery use is the security-sensitive branch SEC-04 wants
            # visible: it means the administrator's authenticator is gone.
            # The code itself is never recorded - only that one was spent.
            await self._audit.add(
                actor_user_id=user_id,
                action="mfa.recovery_code_used",
                entity_type="MfaCredential",
                entity_id=credential.id,
                after_data={"remaining_recovery_codes": remaining},
                request_id=request_id,
                ip_hash=ip_hash,
            )
        else:
            if code is None or not verify_code(
                secret=decrypt_secret(credential.secret_ciphertext), code=code
            ):
                raise InvalidMfaCodeError()
            remaining = await self._recovery.count_unused(credential.id)
            await self._audit.add(
                actor_user_id=user_id,
                action="mfa.verified",
                entity_type="MfaCredential",
                entity_id=credential.id,
                request_id=request_id,
                ip_hash=ip_hash,
            )

        credential.mark_used(now)
        await self._credentials.save(credential)

        return MfaVerifyResult(
            used_recovery_code=recovery_code is not None,
            remaining_recovery_codes=remaining,
        )
