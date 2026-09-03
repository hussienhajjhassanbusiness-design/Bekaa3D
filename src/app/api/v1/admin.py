"""The `/api/v1/admin` security boundary.

Every route mounted on this router inherits `require_admin`, so authentication,
the administrator role and a completed second factor are enforced once here
rather than being repeated - and re-derived, occasionally wrongly - on each
admin endpoint. That single enforcement point is the deliverable of VS-005.

VS-005 deliberately mounts no endpoints of its own: the concrete admin surface
(settings in VS-007, user management in VS-009, the operational queues after
that) arrives with the slices that own it. The boundary is exercised in
production today by `POST /api/v1/auth/mfa/recovery-codes/regenerate`, which
depends on the same `require_admin`.

Note the router-level dependency runs *before* routing resolves to a specific
path, so a non-administrator probing `/api/v1/admin/anything` gets the same 404
whether or not that route exists - which is the point of SEC-10."""

from fastapi import APIRouter, Depends

from app.identity.api.dependencies import require_admin

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])
