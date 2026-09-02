import secrets
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.identity.domain.enums import UserRole
from app.identity.domain.exceptions import (
    AlreadyVerifiedError,
    InvalidPasswordResetTokenError,
    InvalidSessionError,
    InvalidVerificationTokenError,
    PasswordResetTokenExpiredError,
    RefreshTokenReuseError,
    SessionExpiredError,
    SessionRevokedError,
    VerificationTokenExpiredError,
)


@dataclass
class User:
    id: UUID
    email: str
    password_hash: str
    role: UserRole
    email_verified_at: datetime | None
    is_active: bool
    anonymized_at: datetime | None
    deleted_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @property
    def is_verified(self) -> bool:
        return self.email_verified_at is not None

    @property
    def can_authenticate(self) -> bool:
        """Unverified accounts may still log in - they just cannot perform
        protected writes (entities-and-business-rules.md: "Unverified users may
        browse but cannot perform protected write actions"). Only deactivation,
        anonymisation and deletion actually block authentication."""
        return self.is_active and self.anonymized_at is None and self.deleted_at is None

    def mark_verified(self, at: datetime) -> None:
        if self.is_verified:
            raise AlreadyVerifiedError(self.id)
        self.email_verified_at = at
        self.updated_at = at

    def change_password(self, *, new_password_hash: str, at: datetime) -> None:
        """Replace the stored hash.

        Deliberately takes a hash, not a plaintext password: hashing is an
        infrastructure concern (Argon2id), and a domain entity that accepted a
        plaintext password would have to import the hasher and stop being pure.

        Changing the password does not by itself end the user's sessions -
        SEC-08 requires that, but revocation spans the whole `sessions` table
        and so belongs to the use case that owns both repositories."""
        self.password_hash = new_password_hash
        self.updated_at = at


@dataclass
class VerificationToken:
    id: UUID
    user_id: UUID
    token_hash: str
    expires_at: datetime
    used_at: datetime | None
    created_at: datetime

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    def mark_used(self, at: datetime) -> None:
        if self.is_used:
            raise InvalidVerificationTokenError()
        if at >= self.expires_at:
            raise VerificationTokenExpiredError(self.id)
        self.used_at = at


@dataclass
class Session:
    """One browser/device login session, holding rotating refresh-token state.

    Rotation and reuse detection follow database-design.md 5.3 exactly."""

    id: UUID
    user_id: UUID
    refresh_token_hash: str
    token_version: int
    expires_at: datetime
    last_used_at: datetime | None
    rotated_at: datetime | None
    revoked_at: datetime | None
    reuse_detected_at: datetime | None
    ip_hash: str | None
    user_agent: str | None
    created_at: datetime

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_expired(self, at: datetime) -> bool:
        return at >= self.expires_at

    def is_live(self, at: datetime) -> bool:
        return not self.is_revoked and not self.is_expired(at)

    def authorize_rotation(
        self, *, presented_token_hash: str, presented_version: int, at: datetime
    ) -> None:
        """Decide whether a presented refresh token may rotate this session.

        Order matters. The reuse check must come before the hash check: a
        replayed old token fails both, and reporting it as merely "invalid"
        would leave the stolen session alive."""
        if self.is_revoked:
            raise SessionRevokedError(self.id)
        if self.is_expired(at):
            raise SessionExpiredError(self.id)
        if presented_version < self.token_version:
            raise RefreshTokenReuseError(self.id)
        if presented_version != self.token_version:
            raise InvalidSessionError()
        # compare_digest, not ==, so response time cannot leak how many leading
        # characters of the stored hash an attacker has guessed correctly.
        if not secrets.compare_digest(presented_token_hash, self.refresh_token_hash):
            raise InvalidSessionError()

    def rotate(self, *, new_token_hash: str, at: datetime) -> None:
        self.refresh_token_hash = new_token_hash
        self.token_version += 1
        self.rotated_at = at
        self.last_used_at = at

    def revoke(self, at: datetime) -> None:
        if self.is_revoked:
            return
        self.revoked_at = at

    def mark_reuse_detected(self, at: datetime) -> None:
        """Stolen-token response: record the detection and kill the session."""
        self.reuse_detected_at = at
        self.revoke(at)


@dataclass
class PasswordResetToken:
    """A single-use, short-lived permission to replace one account's password.

    Structurally the same as VerificationToken but deliberately a separate type:
    the two prove different things (control of the mailbox vs. authority to
    change a credential), and one shared class would make it possible to redeem
    a verification token on the reset endpoint."""

    id: UUID
    user_id: UUID
    token_hash: str
    expires_at: datetime
    used_at: datetime | None
    created_at: datetime

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    def mark_used(self, at: datetime) -> None:
        # Used is checked before expiry so a replayed token always reads as
        # "invalid" (400) rather than eventually turning into "expired" (410)
        # once its window passes - the status code must not depend on timing.
        if self.is_used:
            raise InvalidPasswordResetTokenError()
        if at >= self.expires_at:
            raise PasswordResetTokenExpiredError(self.id)
        self.used_at = at
