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


class InvalidCredentialsError(IdentityDomainError):
    """Email is unknown, or the password does not match.

    Deliberately one exception for both, so the API cannot accidentally tell an
    attacker which addresses have accounts (FR-02: "Authentication errors must
    not reveal whether an email exists")."""


class AccountDisabledError(IdentityDomainError):
    """Credentials were correct but the account may not authenticate.

    Raised only *after* the password verifies. Someone who already proved they
    know the password learns nothing new from this, so it is safe to be
    specific here while staying enumeration-safe for wrong passwords."""

    def __init__(self, user_id: UUID) -> None:
        super().__init__(f"User {user_id} cannot authenticate.")
        self.user_id = user_id


class AccountLockedError(IdentityDomainError):
    """Too many consecutive failed logins for this email/IP pair (SEC-05).

    Says nothing about whether the account exists - the counter is keyed on
    whatever address was submitted, existing or not."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Too many failed login attempts.")
        self.retry_after_seconds = retry_after_seconds


class InvalidSessionError(IdentityDomainError):
    """This session cannot be used: unknown, mismatched, revoked or expired.

    Base class for the specific reasons below, so a caller that only needs to
    answer "401 or not" can catch this one and cannot accidentally let a new
    subclass escape as a 500."""


class SessionRevokedError(InvalidSessionError):
    def __init__(self, session_id: UUID) -> None:
        super().__init__(f"Session {session_id} is revoked.")
        self.session_id = session_id


class SessionExpiredError(InvalidSessionError):
    def __init__(self, session_id: UUID) -> None:
        super().__init__(f"Session {session_id} has expired.")
        self.session_id = session_id


class SessionTerminatedError(IdentityDomainError):
    """Refresh failed *and* revoked the session as part of failing.

    Callers MUST commit before propagating this. The request itself must return
    401, but a transaction that rolls back on the way out would undo the
    revocation and leave a session alive that was just found to be compromised.
    Deliberately not an InvalidSessionError, so a handler cannot treat it as an
    ordinary rejection and silently skip that commit."""


class RefreshTokenReuseError(SessionTerminatedError):
    """A validly signed refresh token arrived carrying an older token_version.

    The only way that happens is replay of a token that was already rotated
    away - i.e. a stolen token. The caller must revoke the whole session
    (database-design.md 5.3), not merely reject this request."""

    def __init__(self, session_id: UUID) -> None:
        super().__init__(f"Refresh-token reuse detected on session {session_id}.")
        self.session_id = session_id


class SessionOwnerRevokedError(SessionTerminatedError):
    """The session's owner was deactivated, anonymised or deleted after login.

    A session must not outlive its owner's ability to authenticate."""

    def __init__(self, session_id: UUID) -> None:
        super().__init__(f"Owner of session {session_id} can no longer authenticate.")
        self.session_id = session_id


class InvalidRecoveryCodeError(IdentityDomainError):
    """The recovery code is unknown, or it has already been consumed.

    One exception for both, following InvalidVerificationTokenError: telling a
    caller that a code exists but is spent confirms it was once valid, which is
    a detail an attacker working through a stolen list should not get. The API
    surfaces both as the single stable `MFA_INVALID` code."""


class MfaNotEnrolledError(IdentityDomainError):
    """The account has no enabled MFA credential.

    Distinct from a wrong code: nothing was submitted that could have been
    right. Only ever surfaced to a caller who has already authenticated as the
    account in question, so it reveals nothing to an outsider."""


class MfaAlreadyEnabledError(IdentityDomainError):
    """Re-enrollment attempted while MFA is already enabled.

    V1 design assumption. database-design.md 5.6 says enrollment may update the
    credential, but a single `secret_ciphertext` column cannot hold an old and a
    pending secret at once - so an update would either void the working factor
    before the replacement is proven, or leave `enabled_at` set against a secret
    the administrator has not yet confirmed. Both lock the account out of admin.
    Since SEC-04 also treats disabling MFA as not a normal V1 operation,
    replacing an enabled factor is refused here and left to an explicit,
    audited recovery procedure."""


class InvalidMfaCodeError(IdentityDomainError):
    """The submitted TOTP is wrong, malformed, or outside its window.

    One exception for all three: which of them it was is exactly what an
    attacker probing the endpoint would like to learn. Surfaces as the stable
    `MFA_INVALID` code."""


class MfaCodeReplayedError(InvalidMfaCodeError):
    """A genuine TOTP was submitted whose time-step has already been spent.

    Subclasses `InvalidMfaCodeError` so that any handler which does not know
    about replay still refuses the code - failing closed is the only safe
    default here.

    It exists as a distinct type for exactly one reason: this is the branch
    worth recording. A wrong code is noise, but a *correct* code arriving twice
    means one was captured somewhere, and the operator should be able to see
    that. The caller must still answer with the ordinary `MFA_INVALID`;
    admitting "already used" would confirm to an attacker that they hold a real
    code."""
