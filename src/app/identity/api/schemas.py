from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.identity.domain.enums import UserRole


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    # V1 design assumption (SRS §30.3 leaves this to implementation time):
    # 8 characters minimum, no composition rules - BR-120 explicitly favours
    # minimal registration friction over a stricter policy.
    password: str = Field(min_length=8, max_length=256)


class VerifyEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str


class ResendVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class RegistrationAccepted(BaseModel):
    message: str = "If eligible, a verification email has been sent."


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    # No min_length here, unlike RegisterRequest: rejecting a short password at
    # the schema would answer before the throttle runs, turning a 422 into a
    # free oracle for "that password is too short to be this account's".
    password: str = Field(max_length=256)


class SessionRead(BaseModel):
    """What the client learns from a successful login.

    V1 design assumption: api-endpoints.md names `SessionRead` but does not fix
    its fields. Deliberately carries no tokens - those live only in httpOnly
    cookies, and echoing them into a JSON body would hand them straight back to
    any XSS the cookies were meant to defend against."""

    user_id: UUID
    email: EmailStr
    role: UserRole
    email_verified: bool
    session_expires_at: datetime


class PasswordResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class PasswordResetConfirm(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    # Same floor as RegisterRequest, and for the same BR-120 reason. A password
    # set through a reset must be no weaker than one set at registration, so the
    # two constraints are deliberately identical rather than merely similar.
    new_password: str = Field(min_length=8, max_length=256)


class PasswordResetAccepted(BaseModel):
    """Separate from RegistrationAccepted despite the same shape: the message is
    the only thing a caller ever learns from this endpoint, so it must not start
    talking about verification if the registration copy is ever reworded."""

    message: str = "If an account exists for that address, a reset email has been sent."
