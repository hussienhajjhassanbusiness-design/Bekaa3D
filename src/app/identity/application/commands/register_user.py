from app.identity.application.services.verification import (
    issue_verification_email,
    resend_eligible,
)
from app.identity.infrastructure.password_hasher import hash_password
from app.identity.infrastructure.repositories import UserRepository, VerificationTokenRepository
from app.platform.infrastructure.repositories import AuditLogRepository, EmailOutboxRepository


class RegisterUser:
    """Enumeration-safe per SRS §8.1: the caller always gets the same 202 shape
    regardless of which branch below actually ran."""

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
        self,
        *,
        email: str,
        password: str,
        request_id: str | None,
        ip_hash: str | None,
    ) -> None:
        existing = await self._users.get_by_email(email)

        if existing is None:
            user = await self._users.add(email=email, password_hash=hash_password(password))
            await issue_verification_email(
                user=user, token_repo=self._tokens, outbox_repo=self._outbox
            )
            await self._audit.add(
                actor_user_id=user.id,
                action="user.registered",
                entity_type="User",
                entity_id=user.id,
                request_id=request_id,
                ip_hash=ip_hash,
            )
            return

        if not existing.is_verified and await resend_eligible(
            user=existing, token_repo=self._tokens
        ):
            await issue_verification_email(
                user=existing, token_repo=self._tokens, outbox_repo=self._outbox
            )

        # Existing verified account, or not yet resend-eligible: no mutation.
        # Returning silently here (same as the branches above) is what makes this
        # enumeration-safe - the caller cannot distinguish any of these outcomes.
