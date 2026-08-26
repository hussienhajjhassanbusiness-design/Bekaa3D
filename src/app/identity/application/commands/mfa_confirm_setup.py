from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.identity.domain.exceptions import InvalidMfaCodeError, MfaNotEnrolledError
from app.identity.domain.recovery_codes import generate_code_set, normalize_code
from app.identity.infrastructure.repositories import (
    MfaCredentialRepository,
    MfaRecoveryCodeRepository,
)
from app.identity.infrastructure.secret_cipher import decrypt_secret
from app.identity.infrastructure.token_service import hash_token
from app.identity.infrastructure.totp import verify_code
from app.platform.infrastructure.repositories import AuditLogRepository


@dataclass(frozen=True)
class MfaConfirmSetupResult:
    recovery_codes: list[str]
    generated_at: datetime


class ConfirmMfaSetup:
    """Finish enrollment: prove the authenticator works, then enable MFA.

    Enabling only after a real code has been produced is what stops an
    administrator locking themselves out by enrolling against a secret their
    phone never actually stored."""

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
        code: str,
        request_id: str | None,
        ip_hash: str | None,
    ) -> MfaConfirmSetupResult:
        credential = await self._credentials.get_by_user_id(user_id)
        if credential is None:
            raise MfaNotEnrolledError()

        if not verify_code(secret=decrypt_secret(credential.secret_ciphertext), code=code):
            raise InvalidMfaCodeError()

        now = datetime.now(UTC)
        credential.enable(now)
        credential.mark_used(now)
        await self._credentials.save(credential)

        # A first set replaces anything left over from an earlier abandoned
        # enrollment, so codes printed against a discarded secret cannot linger.
        await self._recovery.delete_unused(credential.id)
        codes = generate_code_set()
        await self._recovery.add_set(
            mfa_credential_id=credential.id,
            code_hashes=[hash_token(normalize_code(plaintext)) for plaintext in codes],
        )

        await self._audit.add(
            actor_user_id=user_id,
            action="mfa.enabled",
            entity_type="MfaCredential",
            entity_id=credential.id,
            # Counts only. The codes themselves must never reach an audit row.
            after_data={"recovery_codes_issued": len(codes)},
            request_id=request_id,
            ip_hash=ip_hash,
        )

        return MfaConfirmSetupResult(recovery_codes=codes, generated_at=now)
