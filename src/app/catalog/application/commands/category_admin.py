"""Administrator operations on categories, each atomic with its audit row.

## Locking

`UpdateCategory` and `ArchiveCategory` are read-modify-write operations, so both
take the row lock **before** reading anything they then act on:

    SELECT ... FOR UPDATE  ->  check archived  ->  snapshot "before"
                           ->  mutate          ->  save  ->  audit

Taking the lock first serialises **mutation eligibility and audit truth**.
Unlocked, a PATCH and an archive both observe `deleted_at IS NULL`, both pass the
archived check, and the loser goes on to mutate a row the winner has already
archived - recording a `before` snapshot of a state that was gone by the time
its write landed. With the lock the second transaction blocks, re-reads the
committed row, and is either correctly refused or proceeds against current data.

Break-verification established what the lock is *not* responsible for: removing
it does **not** let a PATCH resurrect an archived row, and does **not** let two
disjoint PATCHes erase each other's fields. SQLAlchemy emits only the columns
each transaction actually changed, so a PATCH that never touched `deleted_at`
cannot clear it. Those protections come from ORM dirty tracking; the lock's own
contribution is the serialisation above.

`CreateCategory` takes no row lock: there is no existing row to lock, and slug
uniqueness is enforced by the partial unique index.

## A guard this slice deliberately does not implement

`database-design.md` 6.1 and `api-endpoints.md` 492 require that a category
cannot be archived while products are still assigned to it (`409
CATEGORY_IN_USE`), with `products.category_id -> categories.id` using
`ON DELETE RESTRICT`.

**VS-011 owns the `products` table, and it does not exist yet.** There is
therefore no query to run and nothing that could be assigned, so the guard is
not implementable here and a test for it could only assert against a table that
is absent. VS-010 ships without it, and there is no decorative test pretending
otherwise.

**VS-011 must add both when it introduces products:**

1. the `ON DELETE RESTRICT` foreign key on `products.category_id`, and
2. a real in-use check in `ArchiveCategory` below, raising `CATEGORY_IN_USE`,
   with a concurrency test for an archive racing a product assignment (FR-04
   requires that race to fail rather than orphan a product).

Until then, archiving always succeeds.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.catalog.domain.entities import Category
from app.catalog.domain.exceptions import (
    ArchivedValueNotMutableError,
    ReferenceValueNotFoundError,
)
from app.catalog.domain.slug import normalise_slug
from app.catalog.infrastructure.repositories import CategoryRepository
from app.platform.application.services.audit_writer import AuditWriter

ENTITY_TYPE = "Category"


@dataclass(frozen=True)
class CategoryMutationResult:
    category: Category
    # Whether anything actually moved. The route does not use it, but the tests
    # do, and it makes the no-op path explicit rather than something inferred
    # from timestamps.
    changed: bool


class CreateCategory:
    def __init__(self, categories: CategoryRepository, audit: AuditWriter) -> None:
        self._categories = categories
        self._audit = audit

    async def execute(
        self,
        *,
        name: str,
        slug: str,
        is_active: bool,
        actor_user_id: UUID,
        request_id: str | None,
        ip_hash: str | None,
    ) -> Category:
        """Insert, then audit - in that order and in one transaction.

        Ordering matters: the insert can fail on the live-slug unique index, and
        auditing afterwards means a rejected create leaves no audit row claiming
        a category was created. `get_session` wraps the request in a single
        transaction, so either both land or neither does.

        Uniqueness is *not* checked by reading first. A `SELECT` followed by an
        `INSERT` has a window between them in which another administrator can
        commit the same slug, and the read would report the slug free when it is
        about to not be. The partial unique index is the only authority; a
        violation is translated to `SlugConflictError` by the repository.
        """
        category = await self._categories.add(
            name=name, slug=normalise_slug(slug), is_active=is_active
        )
        await self._audit.record(
            actor_user_id=actor_user_id,
            action="category.created",
            entity_type=ENTITY_TYPE,
            entity_id=category.id,
            before_data=None,
            after_data=category.audit_snapshot(),
            request_id=request_id,
            ip_hash=ip_hash,
        )
        return category


class UpdateCategory:
    def __init__(self, categories: CategoryRepository, audit: AuditWriter) -> None:
        self._categories = categories
        self._audit = audit

    async def execute(
        self,
        *,
        category_id: UUID,
        name: str | None,
        slug: str | None,
        is_active: bool | None,
        actor_user_id: UUID,
        request_id: str | None,
        ip_hash: str | None,
    ) -> CategoryMutationResult:
        """Partial update. Reactivating a disabled (not archived) row happens
        here, via `is_active=True`."""
        # Locked read first: everything below - the archived check, the audit
        # "before", and the save - has to act on the row as it is now, not as it
        # was before a concurrent transaction committed.
        category = await self._categories.get_by_id_for_update(category_id)
        if category is None:
            raise ReferenceValueNotFoundError(ENTITY_TYPE, category_id)
        if category.is_archived:
            # Archiving is terminal in V1 - there is no restore endpoint - so an
            # archived row is not editable through the ordinary PATCH. With the
            # lock held, a PATCH that lost the race to an archive sees the
            # committed archived state here and is correctly refused.
            raise ArchivedValueNotMutableError(ENTITY_TYPE, category_id)

        before = category.audit_snapshot()
        changed = category.apply_update(
            name=name,
            slug=normalise_slug(slug) if slug is not None else None,
            is_active=is_active,
            at=datetime.now(UTC),
        )
        if changed:
            await self._categories.save(category)

        # Audited whether or not anything moved, following the VS-007
        # convention: a PATCH submitting the values already stored is still an
        # administrator action on a protected resource, and the row then shows
        # equal before/after, which is an accurate description of what happened.
        await self._audit.record(
            actor_user_id=actor_user_id,
            action="category.updated",
            entity_type=ENTITY_TYPE,
            entity_id=category.id,
            before_data=before,
            after_data=category.audit_snapshot(),
            request_id=request_id,
            ip_hash=ip_hash,
        )
        return CategoryMutationResult(category=category, changed=changed)


class ArchiveCategory:
    def __init__(self, categories: CategoryRepository, audit: AuditWriter) -> None:
        self._categories = categories
        self._audit = audit

    async def execute(
        self,
        *,
        category_id: UUID,
        actor_user_id: UUID,
        request_id: str | None,
        ip_hash: str | None,
    ) -> Category:
        """Soft-delete: sets `deleted_at` and clears `is_active` together.

        This is what releases the slug. The unique index is partial on
        `deleted_at IS NULL`, so the archived row leaves the index in the same
        transaction and another category may immediately take the slug - which
        is exactly the behaviour database-design.md 6.1 specifies.

        See the module docstring: the `CATEGORY_IN_USE` guard belongs to VS-011.
        """
        category = await self._categories.get_by_id_for_update(category_id)
        if category is None:
            raise ReferenceValueNotFoundError(ENTITY_TYPE, category_id)
        if category.is_archived:
            raise ArchivedValueNotMutableError(ENTITY_TYPE, category_id)

        before = category.audit_snapshot()
        category.archive(datetime.now(UTC))
        await self._categories.save(category)
        await self._audit.record(
            actor_user_id=actor_user_id,
            action="category.archived",
            entity_type=ENTITY_TYPE,
            entity_id=category.id,
            before_data=before,
            after_data=category.audit_snapshot(),
            request_id=request_id,
            ip_hash=ip_hash,
        )
        return category
