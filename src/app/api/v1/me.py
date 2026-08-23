from fastapi import APIRouter

from app.identity.api.profile import router as identity_profile_router

router = APIRouter()
router.include_router(identity_profile_router)
