from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.identity.domain.enums import UserRole
from app.identity.domain.exceptions import (
    AlreadyVerifiedError,
    InvalidVerificationTokenError,
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

    def mark_verified(self, at: datetime) -> None:
        if self.is_verified:
            raise AlreadyVerifiedError(self.id)
        self.email_verified_at = at
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
