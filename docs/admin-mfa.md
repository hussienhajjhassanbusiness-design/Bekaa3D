# Administrator MFA and the admin security boundary

VS-005. Implements **F-118** (Admin MFA), **SEC-04** (admin MFA treated as
required) and **SEC-10** (admin routes return 404 to non-admins).

Persistence follows [`requirments/database-design.md`](requirments/database-design.md)
§5.6–5.7 exactly: `mfa_credentials` and `mfa_recovery_codes`, no added columns.

Both tables are created by Alembic revision **`c42f47ccac47`**
(`mfa credentials and recovery codes`), which revises `33a9f7a809ea` and is the
single head. Its downgrade drops the `mfa_method` enum type explicitly —
autogenerate omits that, and without it the upgrade/downgrade/upgrade round-trip
CONTRIBUTING.md requires fails on `type "mfa_method" already exists`.

## Enrollment

An administrator enrols once, from an ordinary authenticated session. No admin
route is reachable until this is done.

```
POST /api/v1/auth/mfa/setup            { "current_password": "..." }
  -> 200 { secret, otpauth_uri, issuer, account_name }
```

The password is re-checked even though the caller already holds a valid
session: enrollment decides *what the second factor is*, so a borrowed session
must not be enough to point it at someone else's authenticator.

The response carries the raw TOTP secret. This is the only response in the
system that ever does — feed `otpauth_uri` to an authenticator app (usually as
a QR code) and discard it. The stored copy is encrypted; there is no endpoint
that can show it again.

**MFA is not enabled yet.** `enabled_at` stays `NULL`, so an enrollment that is
started and abandoned leaves the account exactly as it was.

```
POST /api/v1/auth/mfa/setup/confirm    { "code": "123456" }
  -> 200 { recovery_codes: [...10 codes...], generated_at }
```

Confirming proves the authenticator actually stored the secret, which is what
stops an administrator locking themselves out. Only now is `enabled_at` set.

The ten recovery codes are returned **once** and never again — only their
hashes are stored. Print them or put them in a password manager before closing
the response. Confirming also completes MFA for the current session, so there
is no immediate second challenge.

Re-enrolling while MFA is already enabled is refused with `409
INVALID_STATE_TRANSITION`. A single `secret_ciphertext` column cannot hold a
live and a pending secret at once, so allowing it would either void a working
factor before its replacement is proven or mark an unconfirmed secret as
enabled. Both lock the account out.

## Signing in as an administrator

Login is **gated**, not stepped up. An administrator with MFA enabled never
receives a session from `/auth/login` — only a challenge (api-endpoints.md:252):

```
POST /api/v1/auth/login        { "email": "...", "password": "..." }
  -> 202 { challenge_id: "...", expires_in_seconds: 300 }
     No access cookie. No refresh cookie. No CSRF cookie.

POST /api/v1/auth/mfa/verify   { "challenge_id": "...", "code": "123456" }
  -> 204   sets the full auth + CSRF cookie set

GET /api/v1/admin/<anything>
  -> 200
```

A correct password on its own therefore buys nothing but a five-minute
challenge. There is no window in which an administrator holds a real session
without having proved a second factor, and the session that `/verify` creates
is born with the MFA claim already set.

`POST /auth/mfa/verify` is the one authenticated-feeling route in the system
that takes **no session cookie and no CSRF header** — neither exists yet, which
is the entire point. What authenticates the caller is the challenge id: 192
bits of randomness, single-use, five-minute expiry, and issued only to someone
who has already presented the correct password. The rate limit below is what
stands between that and the six-digit TOTP keyspace.

The challenge is **single-use and spent on the attempt**, not on success: a
wrong code burns it and the administrator logs in again for a fresh one. That
costs a mistyped code one extra round trip and denies an attacker a
five-minute window to sit and guess against.

Two cases deliberately do *not* produce a challenge, because in both the
account has no working second factor to prove and challenging it would be a
lockout bug — the endpoints that fix it need the very session the challenge
would be withholding:

- an administrator who has never enrolled;
- an administrator whose enrollment was started but never confirmed
  (`enabled_at IS NULL`).

Both get an ordinary `200` session, which the admin boundary still refuses with
`401 MFA_REQUIRED` until enrollment is confirmed.

MFA completion is *session* state. It survives token rotation on
`POST /api/v1/auth/refresh`, and it disappears when the session does.

## Recovery

If the authenticator is lost, substitute a recovery code for the TOTP at the
same point in the login:

```
POST /api/v1/auth/login        { "email": "...", "password": "..." }
  -> 202 { challenge_id: "...", expires_in_seconds: 300 }

POST /api/v1/auth/mfa/verify   { "challenge_id": "...", "recovery_code": "A7KM-3PQR-XT29" }
  -> 204
```

Codes are case-insensitive and dash-insensitive — they are read off paper, so
`a7km3pqrxt29` works too. Each code works exactly **once**; concurrent attempts
to spend the same one are serialised in the database so exactly one wins.

Replace the set after using one:

```
POST /api/v1/auth/mfa/recovery-codes/regenerate   { "current_password": "..." }
  -> 200 { recovery_codes: [...10 new codes...], generated_at }
```

Regeneration voids every *unused* code and issues ten fresh ones. Already-spent
codes are retained, not deleted: `code_hash` is `UNIQUE` table-wide, and
forgetting that a code was redeemed would let the same string be reissued later
and accepted a second time.

There is no "disable MFA" endpoint. SEC-04 treats admin MFA as required, so
turning it off is not a normal V1 operation. An administrator who loses both
their authenticator and every recovery code needs an out-of-band procedure with
database access — which is exactly why the recovery codes are worth storing
properly.

## The admin boundary

`require_admin` (`src/app/identity/api/dependencies.py`) is the single
enforcement point. `src/app/api/v1/admin.py` applies it to the whole
`/api/v1/admin` prefix, so VS-007 and VS-009 mount routes there and inherit it
rather than repeating the check.

| Caller | Response |
|---|---|
| No session | `401 AUTH_REQUIRED` |
| Authenticated customer | `404 NOT_FOUND` |
| Administrator, enrollment unconfirmed | `401 MFA_REQUIRED` |
| Administrator, MFA complete | proceeds |

The boundary does **not** mint a challenge. Under the login-gated flow the only
source of a challenge is `POST /auth/login`, and an administrator who reaches
the `MFA_REQUIRED` branch is mid-enrollment — they need `/auth/mfa/setup` and
`/setup/confirm`, which their existing session can already call. Handing out a
challenge here would create a second, session-bound route to an MFA-complete
session, which is exactly the parallel authentication path this slice is meant
not to have.

The 404 is SEC-10: a 403 would confirm the route exists. Its `title`, `detail`
and `type` reproduce byte for byte what a genuinely missing route returns —
matching only the status code would leave the wording as an oracle.

## OpenAPI security scheme

`src/app/api/openapi.py` annotates the generated schema so `/docs` describes
what the routes actually require rather than showing everything as public:

| Scheme | Where | Applies to |
|---|---|---|
| `sessionCookie` | `access_token` cookie | every authenticated operation |
| `csrfToken` | `X-CSRF-Token` header | cookie-authenticated **unsafe** methods only |

`POST /auth/login`, `POST /auth/mfa/verify` and the public auth routes are
declared with no security requirement — `/verify` genuinely has none beyond the
challenge in its body, which is the point worth documenting.

This is a post-processing pass over the generated document, not a set of
FastAPI security dependencies on the routes. Declaring `APIKeyCookie` on
`current_claims` or `require_csrf` would put a second credential-reading
mechanism beside the one those functions already implement, in shared VS-003
code, for a documentation-only benefit. No route's runtime behaviour changes.

## Rate limits

Far tighter than the customer auth limits, because a TOTP is only six digits:

| Endpoint | Limit |
|---|---|
| `/auth/mfa/setup` | 5 / hour |
| `/auth/mfa/setup/confirm` | 10 / hour |
| `/auth/mfa/verify` | 10 / 15 min |
| `/auth/mfa/recovery-codes/regenerate` | 5 / hour |

Per-IP, on the shared `rate_limiter`, with the usual `RateLimit-*` headers.
These are V1 design assumptions — the SRS fixes no numbers.

## Audit events

Written through the existing `AuditLogRepository`, `entity_type =
"MfaCredential"`:

| Action | When | Recorded |
|---|---|---|
| `mfa.enrollment_started` | `/setup` | — |
| `mfa.enabled` | `/setup/confirm` | `recovery_codes_issued` |
| `mfa.verified` | TOTP accepted at `/verify` | — |
| `mfa.recovery_code_used` | recovery code accepted at `/verify` | `remaining_recovery_codes` |
| `mfa.recovery_codes_regenerated` | regeneration | `unused_codes_invalidated`, `recovery_codes_issued` |

A completed challenge also writes the ordinary VS-003 `user.logged_in` row
against the new session. A session reached through MFA is still a login, and
splitting the audit vocabulary would make "when did this account sign in?" a
two-query question.

Counts only. No secret, code, hash, password or token is ever written to an
audit row, and `test_recovery_use_is_audited_without_recording_the_code` holds
that line.

## Configuration

```
MFA_SECRET_KEY=<openssl rand -hex 32>    # encrypts stored TOTP secrets
MFA_ISSUER=Bekaa3D                       # shown in the authenticator app
```

`MFA_SECRET_KEY` is separate from `JWT_SIGNING_KEY` and `CSRF_SECRET` on
purpose — one key, one job. **Losing it locks every administrator out of MFA
and forces re-enrollment; leaking it exposes every stored secret.** It is not
rotatable without re-enrolling, since existing ciphertext cannot be read with a
new key.

## Cryptography

Deliberate, and asymmetric between the two kinds of material:

- **TOTP secret — encrypted, not hashed.** Verifying a TOTP means recomputing
  it, which needs the original back. Fernet (AES-128-CBC + HMAC-SHA256) rather
  than raw AES, so tampering with a stored secret fails loudly instead of
  steering it toward an attacker-chosen value.
- **Recovery codes — hashed, and with SHA-256 rather than Argon2id.** The frozen
  schema specifies `code_hash TEXT UNIQUE`, and both the constraint and the
  lookup need a *deterministic* hash; Argon2's random salt would break each.
  The schema therefore picks the algorithm, so security comes from entropy
  instead: 12 characters over a 32-symbol alphabet is 60 bits, which at 10^10
  guesses/second is tens of years per code.

The alphabet excludes `O/0`, `I/1` and `L` because these get transcribed by
hand.

## Outstanding work

- **Admin routes.** VS-005 mounts none — `/api/v1/admin` is the boundary only.
  VS-007 (settings) and VS-009 (user management) add the endpoints.

Everything else this slice deferred is now closed: the Alembic migration
(`c42f47ccac47`) creates both tables, the temporary `mfa_tables` test fixture is
gone, and the recovery-code count plus the four previously undefined MFA
schemas are ratified in
[ADR-017](adr/ADR-017-login-gated-admin-mfa.md).
