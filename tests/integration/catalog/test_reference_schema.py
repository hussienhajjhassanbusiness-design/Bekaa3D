"""The three reference tables as the frozen design specifies them.

Read from PostgreSQL's own catalogue rather than from ORM metadata, because the
question is what the *migration* built - metadata would happily agree with
itself while the migrated database differed.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

LIFECYCLE_COLUMNS = {"id", "name", "is_active", "deleted_at", "created_at", "updated_at"}


@pytest.mark.integration
async def test_categories_match_the_frozen_design(db_engine: AsyncEngine) -> None:
    async with db_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT column_name, data_type, is_nullable "
                    "FROM information_schema.columns WHERE table_name = 'categories'"
                )
            )
        ).all()

    columns = {row[0]: (row[1], row[2]) for row in rows}

    assert set(columns) == LIFECYCLE_COLUMNS | {"slug"}
    assert columns["name"] == ("text", "NO")
    assert columns["slug"] == ("text", "NO")
    assert columns["is_active"] == ("boolean", "NO")
    assert columns["deleted_at"] == ("timestamp with time zone", "YES")
    assert columns["created_at"] == ("timestamp with time zone", "NO")
    assert columns["updated_at"] == ("timestamp with time zone", "NO")


@pytest.mark.integration
async def test_categories_have_no_hierarchy_column(db_engine: AsyncEngine) -> None:
    """V1 has no subcategories. `parent_id` is the likely accident."""
    async with db_engine.connect() as conn:
        names = {
            row[0]
            for row in (
                await conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'categories'"
                    )
                )
            ).all()
        }
    assert "parent_id" not in names


@pytest.mark.integration
@pytest.mark.parametrize("table", ["materials", "colours"])
async def test_simple_reference_tables_match_the_frozen_design(
    db_engine: AsyncEngine, table: str
) -> None:
    async with db_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT column_name, data_type, is_nullable "
                    "FROM information_schema.columns WHERE table_name = :t"
                ),
                {"t": table},
            )
        ).all()

    columns = {row[0]: (row[1], row[2]) for row in rows}

    # No slug: materials and colours are never addressed by URL.
    assert set(columns) == LIFECYCLE_COLUMNS
    assert "slug" not in columns
    assert columns["name"] == ("text", "NO")
    assert columns["deleted_at"] == ("timestamp with time zone", "YES")


@pytest.mark.integration
async def test_the_live_slug_index_exists_and_is_partial(db_engine: AsyncEngine) -> None:
    """The whole slug contract in one object: unique, on `slug`, and partial on
    `deleted_at IS NULL` so archiving releases the value."""
    async with db_engine.connect() as conn:
        definition = await conn.scalar(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE tablename = 'categories' AND indexname = 'ix_categories_live_slug'"
            )
        )

    assert definition is not None, "ix_categories_live_slug is missing"
    assert "UNIQUE" in definition
    assert "(slug)" in definition
    assert "deleted_at IS NULL" in definition


@pytest.mark.integration
@pytest.mark.parametrize("table", ["materials", "colours"])
async def test_names_are_not_unique_on_simple_reference_tables(
    db_engine: AsyncEngine, table: str
) -> None:
    """Stated from the other direction. The frozen design specifies no
    uniqueness on these names, and adding one would reject legitimate
    administrator input - such as re-creating a value whose predecessor was
    archived - for a rule nobody wrote."""
    async with db_engine.connect() as conn:
        unique_indexes = (
            await conn.execute(
                text(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE tablename = :t AND indexdef LIKE '%UNIQUE%'"
                ),
                {"t": table},
            )
        ).all()

    # Only the primary key's implicit unique index may appear.
    for (definition,) in unique_indexes:
        assert "(id)" in definition, f"unexpected unique index on {table}: {definition}"


@pytest.mark.integration
async def test_the_reference_tables_have_no_foreign_keys_yet(db_engine: AsyncEngine) -> None:
    """VS-011 owns products, so nothing references these tables and they
    reference nothing. Guards against a placeholder product FK being scaffolded
    here by accident."""
    async with db_engine.connect() as conn:
        count = await conn.scalar(
            text(
                "SELECT count(*) FROM pg_constraint WHERE contype = 'f' "
                "AND conrelid IN ('categories'::regclass, 'materials'::regclass, "
                "'colours'::regclass)"
            )
        )
    assert count == 0
