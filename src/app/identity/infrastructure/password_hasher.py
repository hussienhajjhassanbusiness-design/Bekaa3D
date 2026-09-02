from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(*, password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerificationError:
        return False


# A fixed hash of a fixed password, used only to burn the same CPU as a real
# verification on code paths that have no password to check. Computed once at
# import so the cost paid per call is exactly one Argon2id verification - the
# same work the real path does - and never a hash of anything secret.
_DUMMY_PASSWORD = "bekaa3d-constant-work-placeholder"
_DUMMY_HASH = _hasher.hash(_DUMMY_PASSWORD)


def perform_dummy_hash() -> None:
    """Spend one Argon2id verification's worth of work and discard the result.

    Anti-enumeration control (SEC-06, api-endpoints.md 195: account existence
    must not leak through "response body, status, or timing"). Branches that
    return without touching a password would otherwise answer in ~8ms while the
    branch that hashes answers in ~80ms, which is a reliable existence oracle.

    This is deliberately real hashing work rather than a sleep: a sleep is
    trivially tuned out by load, and it does not track the hasher's parameters
    if they are ever hardened.
    """
    _hasher.verify(_DUMMY_HASH, _DUMMY_PASSWORD)
