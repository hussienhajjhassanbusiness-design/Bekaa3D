from uuid import UUID


class IdentityDomainError(Exception):
    """Base class for Identity domain errors."""


class AlreadyVerifiedError(IdentityDomainError):
    def __init__(self, user_id: UUID) -> None:
        super().__init__(f"User {user_id} is already verified.")
        self.user_id = user_id


class InvalidVerificationTokenError(IdentityDomainError):
    """Token does not exist, does not match, or has already been used.

    Deliberately not distinguished from "does not exist" at the domain level -
    that distinction must never leak to the caller."""


class VerificationTokenExpiredError(IdentityDomainError):
    def __init__(self, token_id: UUID) -> None:
        super().__init__(f"Verification token {token_id} has expired.")
        self.token_id = token_id
