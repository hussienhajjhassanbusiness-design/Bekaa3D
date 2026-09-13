from uuid import UUID

from sqlalchemy import literal, select, tuple_
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.domain.entities import Category, Colour, Material
from app.catalog.domain.exceptions import SlugConflictError
from app.catalog.infrastructure.models import CategoryModel, ColourModel, MaterialModel

# The partial unique index created by the migration. Compared against the
# driver's reported constraint name when translating an IntegrityError, so an
# unrelated future constraint violation is never mis-reported as a slug
# conflict.
LIVE_SLUG_INDEX = "ix_categories_live_slug"


def _category_to_domain(model: CategoryModel) -> Category:
    return Category(
        id=model.id,
        name=model.name,
        slug=model.slug,
        is_active=model.is_active,
        deleted_at=model.deleted_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _material_to_domain(model: MaterialModel) -> Material:
    return Material(
        id=model.id,
        name=model.name,
        is_active=model.is_active,
        deleted_at=model.deleted_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _colour_to_domain(model: ColourModel) -> Colour:
    return Colour(
        id=model.id,
        name=model.name,
        is_active=model.is_active,
        deleted_at=model.deleted_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _is_live_slug_violation(error: IntegrityError) -> bool:
    """Whether this IntegrityError is specifically the live-slug index.

    Identified structurally rather than by pattern-matching a message. Against a
    real PostgreSQL duplicate the exception chain is:

        sqlalchemy.exc.IntegrityError
          .orig     -> sqlalchemy.dialects.postgresql.asyncpg.IntegrityError
                       (carries `sqlstate`, but no constraint name)
          .orig.__cause__ -> asyncpg.exceptions.UniqueViolationError
                       (carries `constraint_name` and `table_name`)

    so the driver's own `constraint_name` is the authoritative value and is what
    is compared. The substring check is retained only as a fallback for the case
    where the chain is not present - a different driver, or an IntegrityError
    raised without a `__cause__` - and is documented as such rather than being
    the primary mechanism.

    Checked by name either way, so a future NOT NULL or CHECK violation on this
    table can never surface to an administrator as `409 SLUG_CONFLICT`.
    """
    cause = getattr(error.orig, "__cause__", None)
    constraint_name = getattr(cause, "constraint_name", None)
    if isinstance(constraint_name, str):
        return constraint_name == LIVE_SLUG_INDEX
    return LIVE_SLUG_INDEX in str(getattr(error, "orig", error))


class CategoryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, *, name: str, slug: str, is_active: bool) -> Category:
        """Insert and flush.

        The flush is what makes the unique index speak. Without it the INSERT
        would not reach PostgreSQL until commit - long after the route had
        returned a success it could no longer take back.

        No row lock is taken or needed here: there is no existing row to lock,
        and slug uniqueness is enforced by the partial unique index.
        """
        model = CategoryModel(name=name, slug=slug, is_active=is_active)
        self._session.add(model)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            if _is_live_slug_violation(exc):
                raise SlugConflictError(slug) from exc
            raise
        await self._session.refresh(model)
        return _category_to_domain(model)

    async def get_by_id(self, value_id: UUID) -> Category | None:
        """Unlocked read for detail and list endpoints.

        Includes archived rows - administrators may still inspect them.
        """
        model = await self._session.get(CategoryModel, value_id)
        return _category_to_domain(model) if model else None

    async def get_by_id_for_update(self, value_id: UUID) -> Category | None:
        """Read one row and hold a row lock until the transaction ends.

        What the lock is for, established by break-verifying it rather than by
        assumption: **mutation eligibility and audit truth are serialised.**

        Every mutation is a read-modify-write - read the row, decide whether it
        is archived, apply the change, save, audit. Unlocked, two transactions
        both read `deleted_at IS NULL`, both pass the archived check, and the
        loser then mutates a row the winner has already archived while recording
        a `before` snapshot of a state that was gone by the time its write
        landed. With the lock the second transaction blocks, re-reads the
        committed row, and either sees the archived state and is refused or
        proceeds against current data.

        What the lock is **not** doing, despite the obvious guess: it is not what
        stops a PATCH resurrecting an archived row, and not what stops two
        disjoint PATCHes erasing each other's fields. Removing it leaves both of
        those intact, because SQLAlchemy emits only the columns each transaction
        actually changed - a PATCH that never touched `deleted_at` cannot clear
        it. Those are ORM dirty-tracking properties, not lock properties.

        `populate_existing=True` for the reason VS-007 documented: without it a
        row already in this session's identity map is handed back from cache and
        the post-lock read returns pre-lock data - exactly the value the lock
        exists to invalidate.

        The lock is released when the caller's transaction ends, which is the
        end of the request under `get_session`.
        """
        stmt = (
            select(CategoryModel)
            .where(CategoryModel.id == value_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        model = await self._session.scalar(stmt)
        return _category_to_domain(model) if model else None

    async def list_public(self, *, limit: int) -> list[Category]:
        stmt = (
            select(CategoryModel)
            .where(CategoryModel.deleted_at.is_(None), CategoryModel.is_active.is_(True))
            .order_by(CategoryModel.name.asc(), CategoryModel.id.asc())
            .limit(limit)
        )
        return [_category_to_domain(m) for m in (await self._session.scalars(stmt)).all()]

    async def list_page(
        self, *, limit: int, after: tuple[str, UUID] | None = None, include_deleted: bool = False
    ) -> list[Category]:
        stmt = select(CategoryModel)
        if not include_deleted:
            stmt = stmt.where(CategoryModel.deleted_at.is_(None))
        if after is not None:
            after_name, after_id = after
            # Row-value comparison on `(name, id)`. The `id` half is not
            # decoration: `name` is not unique, so without a tie-breaker two
            # rows sharing a name straddle a page boundary - one served twice
            # and the other never.
            stmt = stmt.where(
                tuple_(CategoryModel.name, CategoryModel.id)
                > tuple_(literal(after_name), literal(after_id, postgresql.UUID(as_uuid=True)))
            )
        stmt = stmt.order_by(CategoryModel.name.asc(), CategoryModel.id.asc()).limit(limit)
        return [_category_to_domain(m) for m in (await self._session.scalars(stmt)).all()]

    async def save(self, value: Category) -> None:
        model = await self._session.get(CategoryModel, value.id)
        if model is None:
            raise ValueError(f"Category {value.id} not found")
        model.name = value.name
        model.slug = value.slug
        model.is_active = value.is_active
        model.deleted_at = value.deleted_at
        model.updated_at = value.updated_at
        try:
            await self._session.flush()
        except IntegrityError as exc:
            if _is_live_slug_violation(exc):
                raise SlugConflictError(value.slug) from exc
            raise


# --------------------------------------------------------------------------
# Materials and colours
#
# The two tables are identical in shape, so these classes are deliberately
# parallel rather than clever. Parameter names are shared (`value_id`, `value`)
# so a single typed Protocol in the application layer can cover both - which is
# what keeps the material and colour command classes from being triplicated.
# --------------------------------------------------------------------------


class MaterialRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, *, name: str, is_active: bool) -> Material:
        model = MaterialModel(name=name, is_active=is_active)
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _material_to_domain(model)

    async def get_by_id(self, value_id: UUID) -> Material | None:
        """Unlocked read for detail and list endpoints."""
        model = await self._session.get(MaterialModel, value_id)
        return _material_to_domain(model) if model else None

    async def get_by_id_for_update(self, value_id: UUID) -> Material | None:
        """Locked read for mutations. See CategoryRepository for the reasoning."""
        stmt = (
            select(MaterialModel)
            .where(MaterialModel.id == value_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        model = await self._session.scalar(stmt)
        return _material_to_domain(model) if model else None

    async def list_public(self, *, limit: int) -> list[Material]:
        stmt = (
            select(MaterialModel)
            .where(MaterialModel.deleted_at.is_(None), MaterialModel.is_active.is_(True))
            .order_by(MaterialModel.name.asc(), MaterialModel.id.asc())
            .limit(limit)
        )
        return [_material_to_domain(m) for m in (await self._session.scalars(stmt)).all()]

    async def list_page(
        self, *, limit: int, after: tuple[str, UUID] | None = None, include_deleted: bool = False
    ) -> list[Material]:
        stmt = select(MaterialModel)
        if not include_deleted:
            stmt = stmt.where(MaterialModel.deleted_at.is_(None))
        if after is not None:
            after_name, after_id = after
            stmt = stmt.where(
                tuple_(MaterialModel.name, MaterialModel.id)
                > tuple_(literal(after_name), literal(after_id, postgresql.UUID(as_uuid=True)))
            )
        stmt = stmt.order_by(MaterialModel.name.asc(), MaterialModel.id.asc()).limit(limit)
        return [_material_to_domain(m) for m in (await self._session.scalars(stmt)).all()]

    async def save(self, value: Material) -> None:
        model = await self._session.get(MaterialModel, value.id)
        if model is None:
            raise ValueError(f"Material {value.id} not found")
        model.name = value.name
        model.is_active = value.is_active
        model.deleted_at = value.deleted_at
        model.updated_at = value.updated_at
        await self._session.flush()


class ColourRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, *, name: str, is_active: bool) -> Colour:
        model = ColourModel(name=name, is_active=is_active)
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _colour_to_domain(model)

    async def get_by_id(self, value_id: UUID) -> Colour | None:
        """Unlocked read for detail and list endpoints."""
        model = await self._session.get(ColourModel, value_id)
        return _colour_to_domain(model) if model else None

    async def get_by_id_for_update(self, value_id: UUID) -> Colour | None:
        """Locked read for mutations. See CategoryRepository for the reasoning."""
        stmt = (
            select(ColourModel)
            .where(ColourModel.id == value_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        model = await self._session.scalar(stmt)
        return _colour_to_domain(model) if model else None

    async def list_public(self, *, limit: int) -> list[Colour]:
        stmt = (
            select(ColourModel)
            .where(ColourModel.deleted_at.is_(None), ColourModel.is_active.is_(True))
            .order_by(ColourModel.name.asc(), ColourModel.id.asc())
            .limit(limit)
        )
        return [_colour_to_domain(c) for c in (await self._session.scalars(stmt)).all()]

    async def list_page(
        self, *, limit: int, after: tuple[str, UUID] | None = None, include_deleted: bool = False
    ) -> list[Colour]:
        stmt = select(ColourModel)
        if not include_deleted:
            stmt = stmt.where(ColourModel.deleted_at.is_(None))
        if after is not None:
            after_name, after_id = after
            stmt = stmt.where(
                tuple_(ColourModel.name, ColourModel.id)
                > tuple_(literal(after_name), literal(after_id, postgresql.UUID(as_uuid=True)))
            )
        stmt = stmt.order_by(ColourModel.name.asc(), ColourModel.id.asc()).limit(limit)
        return [_colour_to_domain(c) for c in (await self._session.scalars(stmt)).all()]

    async def save(self, value: Colour) -> None:
        model = await self._session.get(ColourModel, value.id)
        if model is None:
            raise ValueError(f"Colour {value.id} not found")
        model.name = value.name
        model.is_active = value.is_active
        model.deleted_at = value.deleted_at
        model.updated_at = value.updated_at
        await self._session.flush()
