class CatalogDomainError(Exception):
    """Base for catalogue-context domain errors. No HTTP knowledge lives here -
    routers translate these into the SRS-defined stable error codes."""


class ReferenceValueNotFoundError(CatalogDomainError):
    """No category/material/colour exists with this id.

    One error for all three resources, because the API answers all three the
    same way: a 404 that is indistinguishable from the admin boundary's own 404
    for a non-administrator (SEC-10).
    """

    def __init__(self, entity_type: str, entity_id: object) -> None:
        super().__init__(f"No {entity_type} exists with id {entity_id!r}.")
        self.entity_type = entity_type
        self.entity_id = entity_id


class SlugConflictError(CatalogDomainError):
    """Another live row already owns this slug.

    Raised by translating PostgreSQL's unique-violation on the partial index
    rather than by checking first - see `CreateCategory` for why a read-then-
    write check is not the mechanism.
    """

    def __init__(self, slug: str) -> None:
        super().__init__(f"The slug {slug!r} is already in use by a live category.")
        self.slug = slug


class InvalidSlugError(CatalogDomainError):
    """The submitted slug is not a well-formed slug."""

    def __init__(self, slug: str, reason: str) -> None:
        super().__init__(f"Invalid slug {slug!r}: {reason}")
        self.slug = slug
        self.reason = reason


class ArchivedValueNotMutableError(CatalogDomainError):
    """An archived row cannot be changed through the ordinary update endpoint.

    VS-010 ships no restore operation, so archiving is terminal for the normal
    admin surface. The route maps this to the catalogue's existing
    `409 INVALID_STATE_TRANSITION` rather than a new code: "requested
    state-machine transition is illegal" already describes it exactly, and the
    error catalogue is a contract rather than a place to add synonyms.
    """

    def __init__(self, entity_type: str, entity_id: object) -> None:
        super().__init__(f"{entity_type} {entity_id!r} is archived and cannot be modified.")
        self.entity_type = entity_type
        self.entity_id = entity_id
