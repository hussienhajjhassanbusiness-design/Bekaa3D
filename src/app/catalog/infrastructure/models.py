import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# No enums and no seed data in this slice: these tables hold administrator-
# authored values, and there is nothing the schema can know in advance.
#
# `updated_at` carries a server default but deliberately **no** `onupdate`,
# matching SettingModel. The application writes it explicitly, which is what
# lets a PATCH that changes nothing leave the timestamp where it was - with
# `onupdate` the database would bump it on every UPDATE statement and a no-op
# edit would misreport when the row last actually changed.


class CategoryModel(Base):
    """database-design.md 6.1. V1 has no hierarchy, so there is no `parent_id`."""

    __tablename__ = "categories"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # `UNIQUE(slug) WHERE deleted_at IS NULL` - the exact constraint
        # database-design.md 6.1 specifies, and the *only* authority on slug
        # uniqueness. Being partial is what implements "soft-deleting a category
        # releases its slug": an archived row drops out of the index, so the
        # slug becomes available again without any cleanup step.
        #
        # No other index is declared. The frozen design asks for none, the
        # public list is capped at 100 rows, and an index chosen on a hunch is a
        # migration to undo later.
        Index(
            "ix_categories_live_slug",
            "slug",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class MaterialModel(Base):
    """database-design.md 6.2. No slug - a material is never addressed by URL.

    Note there is deliberately no uniqueness constraint on `name`: the frozen
    design specifies none, and inventing one would reject legitimate
    administrator input (for instance re-creating a value whose predecessor was
    archived) for a rule nobody wrote.
    """

    __tablename__ = "materials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ColourModel(Base):
    """database-design.md 6.3. Identical shape to materials."""

    __tablename__ = "colours"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
