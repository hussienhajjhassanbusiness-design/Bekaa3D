"""`/api/v1/admin/{categories,materials,colours}`.

The admin boundary itself is VS-005 work and is not reimplemented here - these
tests check that it is genuinely inherited, then concentrate on what is new:
the three-state lifecycle, slug conflicts, the audit trail, and cursor
pagination.
"""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.infrastructure.models import CategoryModel
from app.platform.infrastructure.models import AuditLogModel
from tests.integration.identity.test_login import PASSWORD, register_and_verify
from tests.integration.identity.test_mfa_enrollment import (
    csrf_headers,
    enrol_admin,
    login,
    login_challenged,
    login_totp,
    make_admin,
    unique_email,
)

CATEGORIES = "/api/v1/admin/categories"
MATERIALS = "/api/v1/admin/materials"
COLOURS = "/api/v1/admin/colours"
VERIFY_PATH = "/api/v1/auth/mfa/verify"


async def _admin_session(client: TestClient, db_session: AsyncSession) -> uuid.UUID:
    """An administrator with a fully MFA-complete session.

    One MFA login per test on purpose: `login_totp` returns a code for a single
    time-step and VS-005's replay guard correctly refuses to accept the same OTP
    twice, so a second login inside one test would fail for a reason that has
    nothing to do with reference data.
    """
    email = unique_email()
    user = await make_admin(client, db_session, email)
    login(client, email)
    secret, _ = enrol_admin(client)
    challenge = login_challenged(client, email)
    completed = client.post(
        VERIFY_PATH, json={"challenge_id": challenge, "code": login_totp(secret)}
    )
    assert completed.status_code == 204, completed.text
    return user.id


def _slug() -> str:
    return f"cat-{uuid.uuid4().hex[:12]}"


def _create_category(client: TestClient, **overrides: Any) -> dict[str, Any]:
    body = {"name": "Lamps", "slug": _slug()} | overrides
    response = client.post(CATEGORIES, json=body, headers=csrf_headers(client))
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


# --------------------------------------------------------------------------
# The admin boundary is inherited, not reimplemented
# --------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
@pytest.mark.parametrize("path", [CATEGORIES, MATERIALS, COLOURS])
def test_an_unauthenticated_caller_is_told_to_authenticate(path: str) -> None:
    from app.main import app

    with TestClient(app) as client:
        client.cookies.clear()
        response = client.get(path)

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_REQUIRED"


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
@pytest.mark.parametrize("path", [CATEGORIES, MATERIALS, COLOURS])
async def test_a_customer_gets_404_not_403(db_session: AsyncSession, path: str) -> None:
    """SEC-10: a 403 would confirm the route exists."""
    from app.main import app

    email = unique_email()
    with TestClient(app) as client:
        await register_and_verify(client, db_session, email)
        client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        response = client.get(path)

    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_an_admin_without_completed_mfa_is_refused(db_session: AsyncSession) -> None:
    from app.main import app

    email = unique_email()
    with TestClient(app) as client:
        await make_admin(client, db_session, email)
        login(client, email)
        response = client.get(CATEGORIES)

    assert response.status_code == 401
    assert response.json()["code"] == "MFA_REQUIRED"


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_unsafe_methods_require_the_csrf_header(db_session: AsyncSession) -> None:
    """SEC-03 covers every unsafe cookie-authenticated method."""
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        created = _create_category(client)

        post = client.post(CATEGORIES, json={"name": "X", "slug": _slug()})
        patch = client.patch(f"{CATEGORIES}/{created['id']}", json={"name": "Y"})
        delete = client.delete(f"{CATEGORIES}/{created['id']}")

    for response in (post, patch, delete):
        assert response.status_code == 403, response.text
        assert response.json()["code"] == "CSRF_INVALID"


# --------------------------------------------------------------------------
# Categories: create, read, update, archive
# --------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_creating_a_category_returns_operational_state(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        created = _create_category(client, name="Desk Lamps")

    assert set(created) == {
        "id",
        "name",
        "slug",
        "is_active",
        "deleted_at",
        "created_at",
        "updated_at",
    }
    assert created["name"] == "Desk Lamps"
    assert created["is_active"] is True
    assert created["deleted_at"] is None


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_a_duplicate_live_slug_is_a_conflict(db_session: AsyncSession) -> None:
    """Enforced by the partial unique index, not by a read-then-write check."""
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        slug = _slug()
        _create_category(client, slug=slug)
        response = client.post(
            CATEGORIES, json={"name": "Other", "slug": slug}, headers=csrf_headers(client)
        )

    assert response.status_code == 409
    assert response.json()["code"] == "SLUG_CONFLICT"


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_a_malformed_slug_is_rejected(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        response = client.post(
            CATEGORIES, json={"name": "Bad", "slug": "Not A Slug"}, headers=csrf_headers(client)
        )

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_an_empty_patch_is_rejected(db_session: AsyncSession) -> None:
    """A PATCH that sets nothing can only mean the caller built the request
    wrongly - distinct from one that submits the values already stored."""
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        created = _create_category(client)
        response = client.patch(
            f"{CATEGORIES}/{created['id']}", json={}, headers=csrf_headers(client)
        )

    assert response.status_code == 422


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_a_disabled_category_can_be_reactivated(db_session: AsyncSession) -> None:
    """The documented route back from `is_active=false`, and the reason disable
    and archive have to stay distinct states."""
    from app.main import app

    with TestClient(app) as client:
        admin_id = await _admin_session(client, db_session)
        created = _create_category(client)
        headers = csrf_headers(client)

        disabled = client.patch(
            f"{CATEGORIES}/{created['id']}", json={"is_active": False}, headers=headers
        )
        public_while_disabled = client.get("/api/v1/categories").json()["items"]
        reactivated = client.patch(
            f"{CATEGORIES}/{created['id']}", json={"is_active": True}, headers=headers
        )
        public_after = client.get("/api/v1/categories").json()["items"]

    assert disabled.json()["is_active"] is False
    assert disabled.json()["deleted_at"] is None, "disabling must not archive"
    assert created["id"] not in {item["id"] for item in public_while_disabled}

    assert reactivated.json()["is_active"] is True
    assert created["id"] in {item["id"] for item in public_after}
    assert admin_id


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_archiving_hides_publicly_but_stays_admin_readable(
    db_session: AsyncSession,
) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        created = _create_category(client)

        archived = client.delete(f"{CATEGORIES}/{created['id']}", headers=csrf_headers(client))
        detail = client.get(f"{CATEGORIES}/{created['id']}")
        public = client.get("/api/v1/categories").json()["items"]

    assert archived.status_code == 204
    assert detail.status_code == 200
    body = detail.json()
    # Archiving sets both columns together.
    assert body["deleted_at"] is not None
    assert body["is_active"] is False
    assert created["id"] not in {item["id"] for item in public}


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_an_archived_category_cannot_be_mutated(db_session: AsyncSession) -> None:
    """V1 ships no restore endpoint, so archiving is terminal for the ordinary
    admin surface. Reuses the catalogue's existing state-machine code rather
    than inventing one."""
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        created = _create_category(client)
        headers = csrf_headers(client)
        client.delete(f"{CATEGORIES}/{created['id']}", headers=headers)

        patched = client.patch(
            f"{CATEGORIES}/{created['id']}", json={"name": "New"}, headers=headers
        )
        rearchived = client.delete(f"{CATEGORIES}/{created['id']}", headers=headers)

    for response in (patched, rearchived):
        assert response.status_code == 409, response.text
        assert response.json()["code"] == "INVALID_STATE_TRANSITION"


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_archiving_releases_the_slug_through_the_api(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        slug = _slug()
        first = _create_category(client, slug=slug)
        client.delete(f"{CATEGORIES}/{first['id']}", headers=csrf_headers(client))
        second = client.post(
            CATEGORIES, json={"name": "Reused", "slug": slug}, headers=csrf_headers(client)
        )

    assert second.status_code == 201, second.text
    assert second.json()["id"] != first["id"]


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_an_unknown_id_is_a_hidden_404(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        response = client.get(f"{CATEGORIES}/{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


# --------------------------------------------------------------------------
# Materials and colours
# --------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
@pytest.mark.parametrize(
    ("path", "public_path"), [(MATERIALS, "/api/v1/materials"), (COLOURS, "/api/v1/colours")]
)
async def test_simple_values_round_trip_through_their_lifecycle(
    db_session: AsyncSession, path: str, public_path: str
) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        headers = csrf_headers(client)

        created = client.post(path, json={"name": "Resin"}, headers=headers)
        assert created.status_code == 201, created.text
        value_id = created.json()["id"]
        assert "slug" not in created.json(), "materials and colours have no slug"

        renamed = client.patch(f"{path}/{value_id}", json={"name": "Tough Resin"}, headers=headers)
        detail = client.get(f"{path}/{value_id}")
        archived = client.delete(f"{path}/{value_id}", headers=headers)
        after_archive = client.get(f"{path}/{value_id}")
        public = client.get(public_path).json()["items"]

    assert renamed.json()["name"] == "Tough Resin"
    assert detail.status_code == 200
    assert archived.status_code == 204
    assert after_archive.json()["deleted_at"] is not None
    assert value_id not in {item["id"] for item in public}


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_duplicate_material_names_are_allowed(db_session: AsyncSession) -> None:
    """The frozen design specifies no uniqueness on these names, so two values
    may legitimately share one."""
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        headers = csrf_headers(client)
        name = f"dup-{uuid.uuid4().hex[:8]}"
        first = client.post(MATERIALS, json={"name": name}, headers=headers)
        second = client.post(MATERIALS, json={"name": name}, headers=headers)

    assert first.status_code == 201
    assert second.status_code == 201, second.text
    assert first.json()["id"] != second.json()["id"]


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


async def _audit_actions(db_session: AsyncSession, actor: uuid.UUID) -> list[str]:
    db_session.expire_all()
    rows = list(
        await db_session.scalars(select(AuditLogModel).where(AuditLogModel.actor_user_id == actor))
    )
    return [row.action for row in rows]


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_every_mutation_is_audited(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        admin_id = await _admin_session(client, db_session)
        headers = csrf_headers(client)
        created = _create_category(client)
        client.patch(f"{CATEGORIES}/{created['id']}", json={"name": "Renamed"}, headers=headers)
        client.delete(f"{CATEGORIES}/{created['id']}", headers=headers)

    actions = await _audit_actions(db_session, admin_id)

    assert "category.created" in actions
    assert "category.updated" in actions
    assert "category.archived" in actions


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_a_no_op_patch_is_audited_without_moving_the_timestamp(
    db_session: AsyncSession,
) -> None:
    """The VS-007 convention: submitting the values already stored is a
    successful request that changes nothing, still audited, with `updated_at`
    describing when the row last actually moved."""
    from app.main import app

    with TestClient(app) as client:
        admin_id = await _admin_session(client, db_session)
        created = _create_category(client, name="Steady")
        response = client.patch(
            f"{CATEGORIES}/{created['id']}",
            json={"name": "Steady"},
            headers=csrf_headers(client),
        )

    assert response.status_code == 200
    assert response.json()["updated_at"] == created["updated_at"]

    db_session.expire_all()
    rows = list(
        await db_session.scalars(
            select(AuditLogModel).where(
                AuditLogModel.actor_user_id == admin_id,
                AuditLogModel.action == "category.updated",
            )
        )
    )
    assert len(rows) == 1
    assert rows[0].before_data == rows[0].after_data


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_a_rejected_create_writes_no_audit_row(db_session: AsyncSession) -> None:
    """Mutation and audit share one transaction."""
    from app.main import app

    with TestClient(app) as client:
        admin_id = await _admin_session(client, db_session)
        slug = _slug()
        _create_category(client, slug=slug)
        refused = client.post(
            CATEGORIES, json={"name": "Refused", "slug": slug}, headers=csrf_headers(client)
        )

    assert refused.status_code == 409

    db_session.expire_all()
    rows = list(
        await db_session.scalars(
            select(AuditLogModel).where(
                AuditLogModel.actor_user_id == admin_id,
                AuditLogModel.action == "category.created",
            )
        )
    )
    assert len(rows) == 1, "only the successful create should be audited"


# --------------------------------------------------------------------------
# Cursor pagination
# --------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_the_admin_cursor_walks_every_row_exactly_once(db_session: AsyncSession) -> None:
    """Every seeded row shares one name.

    That is the point: with distinct names this test passes even with the `id`
    tie-breaker removed, so it would be decorative. Identical names make the
    sort ambiguous unless `id` disambiguates it, and an ambiguous sort serves
    one row twice and another never.
    """
    shared = f"same-{uuid.uuid4().hex[:8]}"
    for _ in range(7):
        db_session.add(CategoryModel(name=shared, slug=_slug(), is_active=True))
    await db_session.commit()

    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)

        seen: list[str] = []
        cursor: str | None = None
        for _ in range(20):
            params: dict[str, Any] = {"limit": 2}
            if cursor:
                params["cursor"] = cursor
            body = client.get(CATEGORIES, params=params).json()
            seen.extend(item["id"] for item in body["items"] if item["name"] == shared)
            cursor = body["next_cursor"]
            if cursor is None:
                break

    assert cursor is None, "pagination did not terminate"
    assert len(seen) == len(set(seen)), f"a row was served twice: {seen}"
    assert len(seen) == 7


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_a_tampered_cursor_is_a_validation_error(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        response = client.get(CATEGORIES, params={"cursor": "!!!not-base64!!!"})

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_the_admin_page_size_is_bounded(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        too_large = client.get(CATEGORIES, params={"limit": 101})
        largest = client.get(CATEGORIES, params={"limit": 100})

    assert too_large.status_code == 422
    assert largest.status_code == 200


@pytest.mark.integration
@pytest.mark.usefixtures("configured_app")
async def test_archived_rows_appear_only_when_asked_for(db_session: AsyncSession) -> None:
    from app.main import app

    with TestClient(app) as client:
        await _admin_session(client, db_session)
        created = _create_category(client)
        client.delete(f"{CATEGORIES}/{created['id']}", headers=csrf_headers(client))

        default_page = client.get(CATEGORIES, params={"limit": 100}).json()
        with_deleted = client.get(CATEGORIES, params={"limit": 100, "include_deleted": True}).json()

    assert created["id"] not in {item["id"] for item in default_page["items"]}
    assert created["id"] in {item["id"] for item in with_deleted["items"]}
