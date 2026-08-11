# Bekaa3D

Backend for Bekaa3D, a dual-commerce platform for a Lebanese 3D-printing business:

- **Physical catalogue** — made-to-order 3D-printed products, sold online, via WhatsApp, or both, per product.
- **STL marketplace** — downloadable 3D model files, sold online only, with permanent entitled access.

## Status

Pre-development. The requirements and architecture are specified and approved; no application code has been written yet (`src/`, `tests/`, and `migrations/` are placeholders). Build order follows the phased plan in the SRS — see [Build Phases](docs/SRS.md#28-build-phases).

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
src/                   # application code (src/bekaa3d/, per pyproject.toml)
tests/                 # unit, integration, contract, e2e, concurrency, security tests
migrations/            # Alembic migrations
docs/
  SRS.md               # authoritative specification
  requirments/          # supporting requirements documents
  adr/                 # architecture decision records
.env.example           # required environment variables — copy to .env
```

## Getting Started

Application code, Docker Compose services, and setup instructions have not been added yet. Once Phase 0 lands, this section will cover local setup (Docker Compose services, database migrations, running the API and worker).

In the meantime: `.env.example` documents the environment variables the application will require (database, Redis, JWT/CSRF secrets, storage paths, Whish, email, captcha, observability).

## Conventions

See [`CLAUDE.md`](CLAUDE.md) for the working conventions used in this codebase (architecture rules, naming, and invariants that must hold under concurrency).
