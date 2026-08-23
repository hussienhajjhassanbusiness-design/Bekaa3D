# Bekaa3D

Backend for Bekaa3D, a dual-commerce platform for a Lebanese 3D-printing business:

- **Physical catalogue** — made-to-order 3D-printed products, sold online, via WhatsApp, or both, per product.
- **STL marketplace** — downloadable 3D model files, sold online only, with permanent entitled access.

## Status

In development, following the vertical-slice plan in [`docs/requirments/vertical-slice-plan.md`](docs/requirments/vertical-slice-plan.md). Merged so far:

- **VS-001** — bootable API, migration baseline, health/readiness, request correlation
- **VS-002** — user registration, email verification, resend, transactional outbox, first worker job
- **VS-003** — login, logout, rotating refresh sessions, CSRF, refresh-token reuse detection

Each slice adds one complete, tested, end-to-end capability. Build order follows the phased plan in the SRS — see [Build Phases](docs/SRS.md#28-build-phases).

## Documentation

[`docs/SRS.md`](docs/SRS.md) is the **single authoritative document** for this project — business rules, features, domain model, database schema, API contract, and non-functional/security requirements. Where anything else conflicts with it, the SRS wins.

Supporting documents in [`docs/requirments/`](docs/requirments/):

| Document | Purpose |
| --- | --- |
| [`project-brief.md`](docs/requirments/project-brief.md) | Business case, scope, constraints, budget, and milestones |
| [`entities-and-business-rules.md`](docs/requirments/entities-and-business-rules.md) | Entity-by-entity model: identity, lifecycle, invariants, deletion strategy |
| [`functional-requirements.md`](docs/requirments/functional-requirements.md) | Gherkin-style functional requirements (FR-01 … FR-19) with negative cases and concurrency behaviour |
| [`non-functional-requirements.md`](docs/requirments/non-functional-requirements.md) | Performance, availability, retention, and capacity targets |
| [`domain-glossary.md`](docs/requirments/domain-glossary.md) | Canonical vocabulary — required naming across code, database, API, and docs |

Architecture decisions get recorded in [`docs/adr/`](docs/adr/) as they're made.

## Stack

| Layer | Technology |
| --- | --- |
| API | Python 3.13, FastAPI, Pydantic v2 |
| ORM | SQLAlchemy 2 (async), Alembic migrations |
| Database | PostgreSQL 16 |
| Queue / cache / rate limits | Redis |
| Worker | arq (jobs and cron) |
| Reverse proxy | nginx (TLS, static, protected file streaming) |
| Scanning | ClamAV |
| Containerisation | Docker Compose |

Architectural style: Clean Architecture (domain → application → infrastructure → API) organized into bounded contexts (Identity, Catalog, Digital Assets, Ordering, Payments, Fulfillment, Negotiation, Engagement, Platform). See [SRS §18](docs/SRS.md#18-architecture).

## Project Layout

```
src/                   # application code (src/app/, per pyproject.toml)
tests/                 # unit, integration, contract, e2e, concurrency, security tests
migrations/            # Alembic migrations
docs/
  SRS.md               # authoritative specification
  requirments/          # supporting requirements documents
  adr/                 # architecture decision records
.env.example           # required environment variables — copy to .env
```

## Getting Started

### Bootstrap

```
cp .env.example .env          # fill in real secrets before anything but local dev
docker compose up -d --build  # postgres, redis, clamav, api
docker compose exec api alembic upgrade head
curl http://localhost:8000/health/live
curl http://localhost:8000/health/ready
```

`.env.example` documents every environment variable the application needs (database, Redis, JWT/CSRF secrets, storage paths, Whish, email, captcha, observability). Note that on this machine host port `5432` is already in use by a native Windows PostgreSQL service (not Docker), so `docker-compose.yml` publishes `postgres` on `5442` instead — change it back to `"5432:5432"` once that conflict is resolved. `api`/`redis`/`clamav` use their standard ports (`8000`/`6379`/`3310`).

For local Python tooling (ruff, mypy, pytest) outside Docker:

```
python -m venv .venv
source .venv/Scripts/activate   # .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy src && pytest
```

### Health endpoints

Both live outside `/api/v1` (they're operational, not business API) and never require authentication:

- `GET /health/live` — process liveness only. Never probes the database or Redis; a slow dependency must never make an orchestrator kill a healthy process. Always `200` if the process is running.
- `GET /health/ready` — checks the dependencies this instance actually needs (Postgres, Redis). Returns `200` with `{"status": "ok", "version", "commit"}` when ready, or a `503` RFC 9457 problem response when a dependency is unreachable. Never includes secrets.

### Migrations

```
docker compose exec api alembic upgrade head        # apply
docker compose exec api alembic revision -m "..."    # new empty revision
```

Migrations run against `DATABASE_URL` from the environment. Alembic is configured for SQLAlchemy's async engine (`migrations/env.py`), so no separate sync driver is needed.

### Request correlation and logging

Every request gets a stable ID (`X-Request-ID`): the incoming header value if the caller supplies one, otherwise a generated `req_<uuid4hex>`. It's echoed back as a response header and bound into every structured log line for that request, and it appears as `request_id` in every error response body. Logs are structured via `structlog` — JSON in production, human-readable console output in development (`ENVIRONMENT` setting).

### Error contract

Every non-2xx API response is `application/problem+json` (RFC 9457): `type`, `title`, `status`, `detail`, `instance`, a stable machine-readable `code`, `request_id`, and an `errors` array for field-level validation failures. Clients should branch on `code`, never on `detail` (which is a diagnostic string, not a translation key). See `docs/requirments/api-endpoints.md` §5 for the full stable error-code table.

### Background jobs (worker)

The `worker` Compose service runs `arq app.worker.WorkerSettings`, sharing one process for both on-demand jobs and cron schedules (arq's `unique=True` cron default means a schedule only fires once even with multiple worker replicas — see `docs/adr/`). Job functions and their schedules live in `src/app/jobs/registry.py`; each job is a plain coroutine that takes an arq `ctx` dict, so it can be unit-tested by calling it directly with a fake `ctx`.

`dispatch_outbox` (every minute, plus once at worker startup) claims due `email_outbox` rows with `SELECT ... FOR UPDATE SKIP LOCKED` — safe with multiple worker replicas — and hands each to the configured email provider. A provider failure never crashes the batch: the message stays `pending` with exponential backoff until it hits 5 attempts, then moves to `failed` and logs at error level.

Watch it locally:

```
docker compose logs -f worker
```

### Registration and email verification (VS-002)

`POST /api/v1/auth/register`, `/verify-email`, and `/resend-verification` are all **enumeration-safe**: the response is identical regardless of whether the email is new, already registered-unverified, or already verified — see `docs/requirments/api-endpoints.md` §8.1. Registration writes the user, verification token, outbox message, and audit-log row in one transaction; the actual email send happens later via the outbox worker, so an email-provider outage never rolls back an account creation.

`EMAIL_PROVIDER=console` (the `.env.example` default) logs the email instead of sending it — grep the `api` or `worker` container logs for `console_email_send` to find a verification link during local development:

```
docker compose logs api worker | grep console_email_send
```

The `token` field in that log entry is the raw value to POST to `/api/v1/auth/verify-email`.

### Browser sessions (VS-003)

`POST /api/v1/auth/login` sets three cookies and returns `SessionRead`. The tokens are never in the response body.

| Cookie | Contents | Lifetime | `httpOnly` | `Path` |
| --- | --- | --- | --- | --- |
| `access_token` | signed JWT: user, session, role, verified flag | `ACCESS_TOKEN_MINUTES` (15) | yes | `/` |
| `refresh_token` | signed JWT: session id + `token_version` | `REFRESH_TOKEN_DAYS` (30) | yes | `/api/v1/auth` |
| `csrf_token` | `HMAC(CSRF_SECRET, session_id)` | 30 days | **no** | `/` |

`csrf_token` is deliberately readable by JavaScript: every unsafe cookie-authenticated request must echo its value in the **`X-CSRF-Token`** header, or the request is rejected with `403 CSRF_INVALID`. Because the token is derived from the session id rather than being a random value, a token minted for one session cannot be replayed against another.

`POST /api/v1/auth/refresh` rotates the refresh token, replaces `sessions.refresh_token_hash`, and increments `token_version`. Rotation does **not** extend `expires_at`, so a session always dies on its original deadline.

**Refresh-token reuse detection.** A validly signed refresh token carrying an *older* `token_version` can only be a replay of a token that was already rotated away. That is treated as theft: `reuse_detected_at` and `revoked_at` are both set, the whole session dies, and a fresh login is required. The response is an ordinary `401 AUTH_REQUIRED` — identical to any other rejected token, so an attacker learns nothing.

A consequence worth knowing: two clients sharing one session (for example two browser tabs refreshing at the same instant) will trip this. The row lock guarantees exactly one rotation succeeds, and the loser is indistinguishable from a replay, so it revokes the session. That is the intended strict-rotation trade-off, not a bug.

Repeated login failures are throttled per `(email, IP)`. Thresholds count **attempts**, not failures already recorded: attempts 1–3 are free, attempts 4–7 wait 1s/2s/4s/8s, 8 and 9 stay at the 8s cap, and the 10th attempt is refused outright for 15 minutes (`429 RATE_LIMITED` with `Retry-After: 900`). Counters live in Redis and reset on a successful login.

## Conventions

See [`CLAUDE.md`](CLAUDE.md) for the working conventions used in this codebase (architecture rules, naming, and invariants that must hold under concurrency).
