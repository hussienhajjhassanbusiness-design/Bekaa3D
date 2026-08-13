from collections.abc import Awaitable, Callable

from fastapi import Request, Response

from app.core.exceptions import ApiError


def rate_limiter(
    *, key_prefix: str, limit: int, window_seconds: int
) -> Callable[[Request, Response], Awaitable[None]]:
    """Fixed-window Redis rate limiter keyed by client IP. Returns a FastAPI
    dependency; raises ApiError(429, RATE_LIMITED) once the window's limit is
    exceeded, otherwise sets standard RateLimit-* response headers."""

    async def dependency(request: Request, response: Response) -> None:
        redis = request.app.state.redis
        client_ip = request.client.host if request.client else "unknown"
        key = f"ratelimit:{key_prefix}:{client_ip}"

        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, window_seconds)
        ttl = await redis.ttl(key)
        reset_seconds = ttl if ttl and ttl > 0 else window_seconds

        headers = {
            "RateLimit-Limit": str(limit),
            "RateLimit-Remaining": str(max(limit - count, 0)),
            "RateLimit-Reset": str(reset_seconds),
        }

        if count > limit:
            raise ApiError(
                status_code=429,
                code="RATE_LIMITED",
                title="Too many requests",
                detail="Rate limit exceeded. Try again later.",
                headers=headers,
            )

        for name, value in headers.items():
            response.headers[name] = value

    return dependency
