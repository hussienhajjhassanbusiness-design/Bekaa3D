from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.identity.domain.exceptions import InvalidCredentialsError, MfaNotEnrolledError
from app.identity.domain.recovery_codes import generate_code_set, normalize_code
from app.identity.infrastructure.password_hasher import verify_password
from app.identity.infrastructure.repositories import (
    MfaCredentialRepository,
    MfaRecoveryCodeRepository,
    UserRepository,
)
from app.identity.infrastructure.token_service import hash_token
from app.platform.infrastructure.repositories import AuditLogRepository


@dataclass(frozen=True)
class MfaRecoveryCodesResult:
    recovery_codes: list[str]
    generated_at: datetime


class RegenerateRecoveryCodes:
    """Replace the unused recovery-code set with a fresh one."""

    def __init__(
        self,
        user_repo: UserRepository,
        credential_repo: MfaCredentialRepository,
        recovery_repo: MfaRecoveryCodeRepository,
        audit_repo: AuditLogRepository,
    ) -> None:
        self._users = user_repo
        self._credentials = credential_repo
        self._recovery = recovery_repo
        self._audit = audit_repo

    async def execute(
        self,
        *,
        user_id: UUID,
        current_password: str,
        request_id: str | None,
        ip_hash: str | None,
    ) -> MfaRecoveryCodesResult:
        user = await self._users.get_by_id(user_id)
        if user is None or not user.can_authenticate:
            raise MfaNotEnrolledError()

        # Regeneration both voids the codes the administrator is holding and
        # mints replacements, so it is worth a password even though the caller
        # is already Admin + MFA.
        if not verify_password(password=current_password, password_hash=user.password_hash):
            raise InvalidCredentialsError()

        credential = await self._credentials.get_by_user_id(user_id)
        if credential is None or not credential.is_enabled:
            raise MfaNotEnrolledError()

        invalidated = await self._recovery.delete_unused(credential.id)
        codes = generate_code_set()
        await self._recovery.add_set(
            mfa_credential_id=credential.id,
            code_hashes=[hash_token(normalize_code(plaintext)) for plaintext in codes],
        )

        await self._audit.add(
            actor_user_id=user_id,
            action="mfa.recovery_codes_regenerated",
            entity_type="MfaCredential",
            entity_id=credential.id,
            # Counts only, on both sides. No code, hash, or password.
            before_data={"unused_codes_invalidated": invalidated},
            after_data={"recovery_codes_issued": len(codes)},
            request_id=request_id,
            ip_hash=ip_hash,
        )

        return MfaRecoveryCodesResult(recovery_codes=codes, generated_at=datetime.now(UTC))
