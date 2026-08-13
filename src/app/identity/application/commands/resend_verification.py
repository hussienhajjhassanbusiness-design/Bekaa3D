from app.identity.application.services.verification import (
    issue_verification_email,
    resend_eligible,
)
from app.identity.infrastructure.repositories import UserRepository, VerificationTokenRepository
from app.platform.infrastructure.repositories import EmailOutboxRepository


class ResendVerification:
    """Uniform response regardless of account existence/state (SRS §8.1) - the
    caller never learns anything from this beyond "request accepted"."""

    def __init__(
        self,
        user_repo: UserRepository,
        token_repo: VerificationTokenRepository,
        outbox_repo: EmailOutboxRepository,
    ) -> None:
        self._users = user_repo
        self._tokens = token_repo
        self._outbox = outbox_repo

    async def execute(self, *, email: str) -> None:
        user = await self._users.get_by_email(email)
        if user is None:
            return
        if not user.is_verified and await resend_eligible(user=user, token_repo=self._tokens):
            await issue_verification_email(
                user=user, token_repo=self._tokens, outbox_repo=self._outbox
            )
