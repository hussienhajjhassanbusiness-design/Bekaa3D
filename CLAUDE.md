# CLAUDE.md

Guidance for Claude Code (and any contributor) working in this repository.

## Source of truth

[`docs/SRS.md`](docs/SRS.md) is the single authoritative specification for Bekaa3D. Business rules (`BR-*`), invariants (`INV-*`), features (`F-*`), functional requirements (`FR-*`), and non-functional/security requirements (`NFR-*`/`SEC-*`) are all numbered there for traceability. If any other document, comment, or prior code conflicts with the SRS, **the SRS wins** — flag the conflict rather than silently picking a side.

Supporting documents, all under [`docs/requirments/`](docs/requirments/):

- `domain-glossary.md` — canonical vocabulary. **Do not invent synonyms.** Use the exact nouns it defines for classes, tables, columns, API resources, and routes.
- `entities-and-business-rules.md` — per-entity identity, lifecycle, invariants, and deletion strategy, labelled by enforcement layer (`[Domain]`, `[DB]`, `[Application]`, `[Authorization]`, `[Worker]`, `[Infrastructure]`).
- `functional-requirements.md` — Gherkin-style requirements per flow, including negative cases, concurrency behaviour, and failure behaviour. Treat the negative/concurrency/failure sections as required test cases, not optional detail.
- `non-functional-requirements.md` — performance, availability, and retention targets.
- `project-brief.md` — business case, scope, and constraints (budget, team size, deadlines).

Record material architectural decisions in `docs/adr/` as they're made, with rationale — don't let context that shaped a decision live only in chat history.

## Project status

Pre-development: `src/`, `tests/`, and `migrations/` are empty. Git has not been initialized yet. Don't assume application code, a database, or Docker services exist until they're actually added — check before referencing them.

## Architecture rules

Clean Architecture, dependencies point inward only:

```
domain        → entities, invariants, pure logic. No framework or database imports.
application   → use cases, orchestration. Depends on domain only.
infrastructure → repositories, external adapters (payment, storage, email, captcha).
api           → routers, schemas. Thin — validation and orchestration live below it.
```

Bounded contexts (each owns its own tables): **Identity, Catalog, Digital Assets, Ordering, Payments, Fulfillment, Negotiation, Engagement, Platform**. Cross-context access goes through service interfaces only — never join directly into another context's tables. That rule is what keeps this a real modular monolith instead of a shared-database free-for-all.

Key ports to code against, not around: payment provider (Whish today, mock for dev/tests), storage (local filesystem today, S3-compatible later), email provider, captcha provider. A repository per aggregate isolates persistence from domain logic.

## Non-negotiable invariants

These are the ones that cause real financial or security damage if violated — see SRS §19.2, §26 for the full list:

- **Money** is always integer cents plus an explicit currency code. Never floats. Prices/shipping/totals are always recomputed server-side — client-supplied amounts are never trusted.
- **A payment callback is a notification, never proof.** `paid` is reachable only through independent server-side verification (status query, or documented manual admin confirmation). Never name a webhook handler `confirm_payment()` or `mark_as_paid()` — see glossary rule 6.
- **Idempotency** is required on checkout and refunds via the `Idempotency-Key` header; webhook idempotency is by unique `(provider, event_id)`.
- **Entitlement is the sole authority for STL download access** — never derive download permission from an OrderItem or Payment directly. At most one active entitlement per `(user, product)`, enforced at the DB.
- **Order status is a derived projection**, recomputed from payment + line state in the same transaction as the change that caused it. Never assign `order.status` directly.
- Business invariants that must survive concurrency (one live payment per order, one live offer per customer/product, unique cart line per product, STL quantity always 1, etc.) belong in **database constraints**, not just application checks — application checks lose races.
- Nothing is hard-deleted. Use soft delete (`deleted_at`) or anonymization; some records (payments, refunds, audit log, asset versions) are retained permanently.
- All timestamps are `timestamptz`, stored UTC, never naive.

## Naming (see `domain-glossary.md` for the full table)

- Use the canonical noun: `Cart`, `Order`, `OrderItem`, `Payment`, `Refund`, `Entitlement`, `Offer`, `CustomRequest`, `Notification` — not basket/sale/transaction/license/bid/idea-order.
- `User` is the persisted entity; `Verified Customer` / `Administrator` are roles on a `User`, not separate entities.
- `ProductType` (physical/STL), `PurchaseMode` (online/WhatsApp/both), and `FulfillmentMethod` (delivery/pickup) are three separate concepts — never collapse them into one enum or column.
- Order-time immutable values get an explicit `_snapshot` suffix (`product_name_snapshot`, `unit_price_cents`, `address_snapshot`, …) so they're never confused with live catalogue/profile data.
- Each entity owns its own `status` (`order_item.fulfillment_status`, `payment.status`, `offer.status`, …) — no shared generic `status` field across contexts.

## Testing

- `pytest` markers: `integration` (needs a live Postgres), `concurrency` (exercises race conditions). Use them.
- Constraints that live in the database (unique indexes, checks) must be tested against real PostgreSQL, not SQLite or a mock — a mock asserts nothing about a partial index.
- The SRS's mandatory coverage callout: the mixed-order partial-refund path is the most bug-prone area in the system and needs deliberately heavy test coverage.
- `ruff` (line-length 100, py313 target) and `mypy --strict` are both configured in `pyproject.toml`; keep new code passing both rather than adding ignores.

## Working style

- Don't add scope beyond what the SRS specifies for the current phase — the budget and timeline constraints in `project-brief.md` are real and tight. If a task seems to require expanding scope, flag it rather than quietly building it.
- When a requirement is genuinely ambiguous or the SRS marks it an open decision (§30), say so instead of guessing silently.
