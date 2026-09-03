"""VS-005: the OpenAPI security scheme for the cookie-authenticated API.

Required by the VS-005 deliverable list ("Admin enrollment/recovery runbook and
OpenAPI security scheme", vertical-slice-plan.md:128). Without it the generated
schema shows every route as though it were public, which is misleading in the
one place a client integrator is most likely to look.

Deliberately implemented as a post-processing pass over the generated schema
rather than as FastAPI security dependencies on the routes themselves. Adding
`APIKeyCookie(...)` to `current_claims` or `require_csrf` would put a second
credential-reading mechanism next to the one those functions already implement,
in shared VS-003 code, for a documentation-only benefit. This changes no route's
runtime behaviour at all - it only describes what the routes already do."""

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app.api.cookies import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE
from app.identity.api.dependencies import CSRF_HEADER

_SECURITY_SCHEMES: dict[str, Any] = {
    "sessionCookie": {
        "type": "apiKey",
        "in": "cookie",
        "name": ACCESS_COOKIE,
        "description": (
            "Short-lived signed access token, set httpOnly by "
            "`POST /auth/login` or `POST /auth/mfa/verify` (ADR-006). The "
            f"browser sends it automatically; `{REFRESH_COOKIE}` rotates it "
            "through `POST /auth/refresh`."
        ),
    },
    "csrfToken": {
        "type": "apiKey",
        "in": "header",
        "name": CSRF_HEADER,
        "description": (
            f"Double-submit CSRF defence (SEC-03). Copy the readable "
            f"`{CSRF_COOKIE}` cookie into this header on every "
            "cookie-authenticated unsafe method."
        ),
    },
}

# Routes that authenticate by something other than a session cookie, and so
# must not be described as requiring one.
_UNAUTHENTICATED_PATHS = frozenset(
    {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/verify-email",
        "/api/v1/auth/resend-verification",
        # Authenticated by the single-use login challenge in its body, before
        # any session exists (api-endpoints.md:270).
        "/api/v1/auth/mfa/verify",
        "/health",
        "/health/ready",
    }
)

_SAFE_METHODS = frozenset({"get", "head", "options"})


def _requirements(path: str, method: str) -> list[dict[str, list[str]]] | None:
    """What a caller must present for one operation, or None if it is public.

    CSRF is required only for cookie-authenticated unsafe methods, which is
    exactly the rule `require_csrf` enforces - a `GET` never carries the header,
    so claiming it does would send integrators chasing a token they don't need."""
    if path in _UNAUTHENTICATED_PATHS:
        return None
    if method in _SAFE_METHODS:
        return [{"sessionCookie": []}]
    return [{"sessionCookie": [], "csrfToken": []}]


def custom_openapi(app: FastAPI) -> dict[str, Any]:
    """Generate the schema once, annotate it, and cache it on the app.

    Caching is FastAPI's own convention (`app.openapi_schema`): the schema is
    deterministic and rebuilding it per request is pure waste."""
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=(
            "Bekaa3D API. Authentication is cookie-based (ADR-006): short-lived "
            "access tokens and rotating refresh tokens in httpOnly cookies, with "
            "double-submit CSRF on unsafe methods.\n\n"
            "Administrator routes under `/api/v1/admin` additionally require a "
            "completed second factor (SEC-04). An administrator with MFA enabled "
            "receives `202 MfaChallengeRead` from `POST /auth/login` instead of a "
            "session, and completes login at `POST /auth/mfa/verify`. A route "
            "under `/api/v1/admin` answers `404` rather than `403` to an "
            "authenticated non-administrator (SEC-10), so its absence from a "
            "caller's view is not evidence that it does not exist."
        ),
        routes=app.routes,
    )

    schema.setdefault("components", {})["securitySchemes"] = _SECURITY_SCHEMES

    for path, operations in schema.get("paths", {}).items():
        for method, operation in operations.items():
            if not isinstance(operation, dict):
                continue
            requirements = _requirements(path, method.lower())
            if requirements is not None:
                operation["security"] = requirements

    app.openapi_schema = schema
    return schema
