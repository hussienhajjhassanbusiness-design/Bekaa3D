# Contributing

Short, practical rules for working on Bekaa3D with more than one person. For architecture, naming, and invariants see [`CLAUDE.md`](CLAUDE.md); the specification itself is [`docs/SRS.md`](docs/SRS.md).

## Branching and review

- **No direct commits to `master`.** Every change arrives through a pull request, including one-line documentation fixes.
- **One branch per vertical slice.** Name it after the slice: `vs-004-password-reset`. Non-slice work uses a prefix: `chore/`, `docs/`, `fix/`.
- **Pull `master` before starting a slice**, and again before opening the PR:

  ```bash
  git checkout master
  git pull
  git checkout -b vs-004-password-reset
  ```

- **A PR needs review and green CI before it merges.** CI runs `ruff check`, `ruff format --check`, `mypy src`, and the full `pytest` suite. Don't merge on `mergeable_state: unstable` — that means checks are still running.
- Keep a slice's PR self-contained: it should not depend on unfinished work in another branch (Definition of Done, `docs/requirments/vertical-slice-plan.md` §6).

## The Alembic migration lock

**Only one person may be creating a migration at any time.**

Alembic's history is a linked list: each revision names the one before it in `down_revision`. When two branches are cut from the same head and both run `alembic revision`, both new revisions point back at that same parent, and the chain forks:

```
              ┌─ VS-004 migration
A (head) ─────┤
              └─ VS-005 migration      ← two heads. Broken.
```

What the chain must look like:

```
A ──→ VS-004 migration ──→ VS-005 migration      ← one head. Correct.
```

The fork surfaces as `Multiple head revisions are present` on the next `alembic upgrade head`, and it blocks *everyone* until it is resolved.

### The protocol

1. **Announce it** before running `alembic revision` — "I'm taking the migration lock." Message, call, whatever you use; the point is that the other person knows.
2. **The other developer waits.** Not "starts a migration carefully" — waits. Keep working on domain, application, API, and test code, which need no lock.
3. **Merge your migration PR**, then say the lock is free.
4. **The other developer pulls `master`** and only then runs `alembic revision`. Their new revision now points at yours, and the chain stays linear.

Hold the lock for as short a time as you can. If a slice needs a migration, generate it early and get that PR merged rather than sitting on the lock while the rest of the slice is built.

### Before merging any migration PR

Run both, and don't merge unless both pass:

```bash
docker compose exec api alembic heads          # must list exactly ONE revision
docker compose exec api alembic upgrade head   # must succeed
```

Also confirm the migration is reversible — `alembic downgrade -1` then `alembic upgrade head` — before you open the PR. A migration that cannot be undone is a migration you cannot roll back in production.

### If you do end up with two heads

**Do not casually edit `down_revision` to stitch them together.** It looks like it works, and it silently reorders DDL that may depend on ordering — a column added by one branch, indexed by the other. Instead:

- If neither migration has been merged, the cheapest fix is to delete the later revision file, pull `master`, and regenerate it against the correct parent.
- If both are already on `master`, use `alembic merge` to create an explicit merge revision, and have the second person review it. Editing `down_revision` by hand is a last resort and never done alone.

## Local checks before opening a PR

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

Integration and concurrency tests need Docker running — they start real PostgreSQL and Redis containers.

## Secrets

`.env` is git-ignored and must never be committed. Copying `.env.example` is not enough: replace every placeholder with a locally generated value. See the **Local secrets** section in [`CLAUDE.md`](CLAUDE.md) for why `IP_HASH_SALT` in particular matters.
