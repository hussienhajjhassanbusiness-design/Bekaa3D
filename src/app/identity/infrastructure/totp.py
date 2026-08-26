"""RFC 6238 TOTP, delegated to pyotp.

Nothing here implements the algorithm itself. HOTP/TOTP is easy to write and
easy to write subtly wrong - constant-time comparison, counter windows, base32
padding - and a mistake in any of those weakens the admin boundary silently."""

import pyotp

from app.core.config import get_settings

# One step either side of now, i.e. roughly +/-30s. Enough for a phone whose
# clock has drifted or an administrator typing the last digit as the code
# rolls; wider would meaningfully enlarge the window a stolen code stays live.
_VALID_WINDOW = 1

# 160 bits, the RFC 4226 recommendation, encoded as 32 base32 characters.
_SECRET_LENGTH = 32


def generate_secret() -> str:
    """A fresh base32 TOTP secret. pyotp uses `secrets` underneath."""
    return pyotp.random_base32(length=_SECRET_LENGTH)


def provisioning_uri(*, secret: str, account_name: str) -> str:
    """The `otpauth://` URI an authenticator app consumes, usually via QR.

    Note this embeds the raw secret - it is setup material, returned once and
    never logged or persisted."""
    settings = get_settings()
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=settings.mfa_issuer)


def verify_code(*, secret: str, code: str) -> bool:
    """Check a submitted code against the secret.

    pyotp compares in constant time, so a wrong code cannot be narrowed down by
    timing. Non-numeric or malformed input simply fails rather than raising -
    the caller's answer is the same either way, and distinguishing them would
    hand an attacker a free oracle for what the server considers well-formed."""
    return bool(pyotp.TOTP(secret).verify(code.strip(), valid_window=_VALID_WINDOW))
