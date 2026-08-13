from pydantic import BaseModel, ConfigDict, EmailStr, Field


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
