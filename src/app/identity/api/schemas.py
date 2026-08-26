from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

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


class MfaSetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(max_length=256)


class MfaSetupConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=6, max_length=10)


class MfaVerifyRequest(BaseModel):
    """api-endpoints.md 29.2: "Exactly one second-factor credential is supplied."

    Enforced rather than merely documented, so a caller cannot send both and
    leave the server to pick - which factor was actually checked would then
    depend on evaluation order rather than on the request."""

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(max_length=128)
    code: str | None = Field(default=None, min_length=6, max_length=10)
    recovery_code: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def exactly_one_factor(self) -> "MfaVerifyRequest":
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("Supply exactly one of `code` or `recovery_code`.")
        return self


class MfaRecoveryRegenerateRequest(BaseModel):
    """V1 design assumption: api-endpoints.md names this schema in the endpoint
    table but never lists its fields. Mirrors `MfaSetupRequest` - regeneration
    voids the codes the administrator currently holds, so it is re-authenticated
    the same way enrollment is."""

    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(max_length=256)


class MfaSetupRead(BaseModel):
    """Enrollment material, returned exactly once by `/auth/mfa/setup`.

    V1 design assumption: api-endpoints.md fixes the name and says "Returns TOTP
    setup material once; secret remains protected", without listing fields.

    This is the one response in the system that deliberately carries a secret,
    because an authenticator app cannot be provisioned without it. It is never
    returned again: `/setup/confirm` and everything after it expose only state,
    and the stored copy is encrypted."""

    secret: str
    otpauth_uri: str
    issuer: str
    account_name: str


class MfaRecoveryCodesRead(BaseModel):
    """The one-time plaintext codes, returned only at generation/regeneration.

    V1 design assumption: named in api-endpoints.md without a field list. Only
    hashes are stored, so there is no endpoint that can ever show these again -
    which is the point, and worth the client telling the administrator."""

    recovery_codes: list[str]
    generated_at: datetime


class MfaChallengeRead(BaseModel):
    """The `202` body from `POST /auth/login` when an administrator still owes
    a second factor (api-endpoints.md:252).

    V1 design assumption: api-endpoints.md names this schema but never lists
    its fields. `challenge_id` is the minimum the client needs in order to call
    `/auth/mfa/verify`; `expires_in_seconds` saves it from having to discover
    the five-minute window by being rejected.

    Note what is deliberately absent. No user id, no email, no role, no
    indication of which second factors are available - the caller has proven a
    password and nothing more, and this response is not the place to confirm
    who the account belongs to or that it is an administrator."""

    challenge_id: str
    expires_in_seconds: int
