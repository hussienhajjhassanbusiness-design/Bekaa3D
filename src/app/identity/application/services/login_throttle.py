"""Progressive delay and lockout on repeated login failure (SEC-05).

State lives in Redis, not Postgres. The frozen `users` table has no
failed-attempt columns and database-design.md never adds any, so counting in
the database would mean deviating from the frozen schema - and a counter that
resets on success is exactly what Redis expiry is for.

V1 design assumption: SEC-05 mandates "progressive delay and lockout" but the
SRS specifies no thresholds, so these numbers are chosen here (same convention
as the VS-002 rate limits in identity/api/auth.py) and documented as such."""

import asyncio
import hashlib
from typing import Any

from app.identity.domain.exceptions import AccountLockedError

# First three attempts cost nothing - a customer who mistypes twice should not
# be punished. After that each attempt doubles the wait, capped so a request
# never occupies a worker for long.
#
# Every threshold here counts *attempts*, not failures already recorded. The two
# differ by one, and conflating them is exactly the bug this module once had.
FREE_ATTEMPTS = 3
MAX_DELAY_SECONDS = 8.0
LOCKOUT_AT_ATTEMPT = 10
LOCKOUT_SECONDS = 15 * 60


def _delay_for(attempt: int) -> float:
    """Delay before the Nth attempt: 4 -> 1s, 5 -> 2s, 6 -> 4s, 7+ -> 8s."""
    if attempt <= FREE_ATTEMPTS:
        return 0.0
    return min(float(2 ** (attempt - FREE_ATTEMPTS - 1)), MAX_DELAY_SECONDS)


class LoginThrottle:
    def __init__(self, redis: Any) -> None:
        self._redis = redis

    @staticmethod
    def _key(email: str, ip: str | None) -> str:
        # The email is hashed so Redis never holds a plaintext list of the
        # addresses people are trying to log in with. Keyed by email *and* IP so
        # one attacker cannot lock a victim out of their own account from afar.
        digest = hashlib.sha256(email.lower().encode("utf-8")).hexdigest()[:32]
        return f"login-throttle:{digest}:{ip or 'unknown'}"

    async def check(self, *, email: str, ip: str | None) -> None:
        """Raise if locked out, otherwise sleep for the current penalty.

        Called before credentials are verified, so the delay applies whether or
        not this attempt turns out to be correct - a timing difference here
        would tell an attacker their guess was close."""
        raw = await self._redis.get(self._key(email, ip))
        failures = int(raw) if raw else 0
        # Redis holds the failures already recorded, so this request is the one
        # after them. The policy is written in attempt numbers, so convert
        # before applying it - passing `failures` straight through is what once
        # granted a fourth free guess and pushed the lockout to attempt 11.
        attempt = failures + 1

        if attempt >= LOCKOUT_AT_ATTEMPT:
            raise AccountLockedError(retry_after_seconds=LOCKOUT_SECONDS)

        delay = _delay_for(attempt)
        if delay:
            await asyncio.sleep(delay)

    async def record_failure(self, *, email: str, ip: str | None) -> None:
        key = self._key(email, ip)
        await self._redis.incr(key)
        # Refreshed on every failure, so the window slides: an attacker who
        # keeps trying stays locked, and someone who walks away is forgiven.
        await self._redis.expire(key, LOCKOUT_SECONDS)

    async def reset(self, *, email: str, ip: str | None) -> None:
        await self._redis.delete(self._key(email, ip))
