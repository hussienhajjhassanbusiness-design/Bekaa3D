from fastapi import APIRouter

from app.identity.api.auth import router as identity_auth_router

router = APIRouter()
router.include_router(identity_auth_router)
