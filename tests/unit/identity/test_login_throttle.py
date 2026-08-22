import pytest

from app.identity.application.services.login_throttle import (
    LOCKOUT_AFTER,
    LOCKOUT_SECONDS,
    LoginThrottle,
    _delay_for,
)
from app.identity.domain.exceptions import AccountLockedError


class FakeRedis:
    """Just enough Redis to exercise the policy without a container."""

    def __init__(self, initial: dict[str, int] | None = None) -> None:
        self.values: dict[str, int] = dict(initial or {})
        self.expiries: dict[str, int] = {}

    async def get(self, key: str) -> bytes | None:
        value = self.values.get(key)
        return str(value).encode() if value is not None else None

    async def incr(self, key: str) -> int:
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.expiries[key] = seconds

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)


@pytest.mark.parametrize(
    ("failures", "expected"),
    [(0, 0.0), (1, 0.0), (2, 0.0), (3, 0.0), (4, 1.0), (5, 2.0), (6, 4.0), (7, 8.0), (20, 8.0)],
)
def test_delay_curve_matches_the_agreed_policy(failures: int, expected: float) -> None:
    assert _delay_for(failures) == expected


async def test_lockout_raises_once_the_threshold_is_reached() -> None:
    redis = FakeRedis()
    throttle = LoginThrottle(redis)
    key = LoginThrottle._key("someone@example.com", "1.2.3.4")
    redis.values[key] = LOCKOUT_AFTER

    with pytest.raises(AccountLockedError) as excinfo:
        await throttle.check(email="someone@example.com", ip="1.2.3.4")

    assert excinfo.value.retry_after_seconds == LOCKOUT_SECONDS


async def test_a_fresh_email_ip_pair_is_not_delayed() -> None:
    throttle = LoginThrottle(FakeRedis())

    await throttle.check(email="someone@example.com", ip="1.2.3.4")


async def test_failures_are_counted_and_the_window_slides() -> None:
    redis = FakeRedis()
    throttle = LoginThrottle(redis)

    await throttle.record_failure(email="someone@example.com", ip="1.2.3.4")
    await throttle.record_failure(email="someone@example.com", ip="1.2.3.4")

    key = LoginThrottle._key("someone@example.com", "1.2.3.4")
    assert redis.values[key] == 2
    assert redis.expiries[key] == LOCKOUT_SECONDS


async def test_a_successful_login_clears_the_counter() -> None:
    redis = FakeRedis()
    throttle = LoginThrottle(redis)
    await throttle.record_failure(email="someone@example.com", ip="1.2.3.4")

    await throttle.reset(email="someone@example.com", ip="1.2.3.4")

    assert redis.values == {}


def test_the_counter_key_never_contains_the_plaintext_email() -> None:
    key = LoginThrottle._key("someone@example.com", "1.2.3.4")

    assert "someone@example.com" not in key
    assert "1.2.3.4" in key


def test_the_key_is_case_insensitive_on_email() -> None:
    """users.email is CITEXT, so Alice@x.com and alice@x.com are one account
    and must share one counter - otherwise changing case resets the lockout."""
    assert LoginThrottle._key("Alice@Example.com", "1.2.3.4") == LoginThrottle._key(
        "alice@example.com", "1.2.3.4"
    )


def test_different_ips_are_counted_separately() -> None:
    """Keyed on email *and* IP so a remote attacker cannot lock a victim out of
    their own account by guessing badly from somewhere else."""
    assert LoginThrottle._key("a@example.com", "1.2.3.4") != LoginThrottle._key(
        "a@example.com", "5.6.7.8"
    )
