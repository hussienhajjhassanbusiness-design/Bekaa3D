from app.identity.application.services.verification import (
    issue_verification_email,
    resend_eligible,
)
from app.identity.infrastructure.password_hasher import perform_dummy_hash
from app.identity.infrastructure.repositories import UserRepository, VerificationTokenRepository
from app.platform.infrastructure.repositories import AuditLogRepository, EmailOutboxRepository


class ResendVerification:
    """Uniform response regardless of account existence/state (SRS 8.1) - the
    caller never learns anything from this beyond "request accepted"."""

    def __init__(
        self,
        user_repo: UserRepository,
        token_repo: VerificationTokenRepository,
        outbox_repo: EmailOutboxRepository,
        audit_repo: AuditLogRepository,
    ) -> None:
        self._users = user_repo
        self._tokens = token_repo
        self._outbox = outbox_repo
        self._audit = audit_repo

    async def execute(
        self, *, email: str, request_id: str | None = None, ip_hash: str | None = None
    ) -> None:
        user = await self._users.get_by_email(email)

        if user is None or not (
            not user.is_verified and await resend_eligible(user=user, token_repo=self._tokens)
        ):
            # Unknown address, already verified, or still inside the cooldown.
            # All three return without writing anything, and all three would
            # therefore answer far faster than the issuing branch below, which
            # writes a token row and an outbox row. Burning one Argon2id
            # verification here makes the hashing cost - not the handful of
            # milliseconds of database work - dominate every branch, so response
            # time stops distinguishing them (SEC-06).
            perform_dummy_hash()
            return

        await issue_verification_email(user=user, token_repo=self._tokens, outbox_repo=self._outbox)
        # BR-132 requires every auth event to be audit-logged, and SRS 22.4
        # classifies resend-verification as an authentication endpoint. Written
        # only when mail is actually issued, matching RequestPasswordReset: an
        # audit row for a non-event would be noise, and the row is server-side
        # so it leaks nothing to the caller either way.
        await self._audit.add(
            actor_user_id=user.id,
            action="user.verification_resent",
            entity_type="User",
            entity_id=user.id,
            request_id=request_id,
            ip_hash=ip_hash,
        )
