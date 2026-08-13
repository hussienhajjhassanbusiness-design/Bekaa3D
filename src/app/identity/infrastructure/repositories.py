from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.identity.domain.entities import User, VerificationToken
from app.identity.infrastructure.models import UserModel, VerificationTokenModel


def _user_to_domain(model: UserModel) -> User:
    return User(
        id=model.id,
        email=str(model.email),
        password_hash=model.password_hash,
        role=model.role,
        email_verified_at=model.email_verified_at,
        is_active=model.is_active,
        anonymized_at=model.anonymized_at,
        deleted_at=model.deleted_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _token_to_domain(model: VerificationTokenModel) -> VerificationToken:
    return VerificationToken(
        id=model.id,
        user_id=model.user_id,
        token_hash=model.token_hash,
        expires_at=model.expires_at,
        used_at=model.used_at,
        created_at=model.created_at,
    )


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(UserModel).where(UserModel.email == email, UserModel.deleted_at.is_(None))
        model = await self._session.scalar(stmt)
        return _user_to_domain(model) if model else None

    async def get_by_id(self, user_id: UUID) -> User | None:
        model = await self._session.get(UserModel, user_id)
        return _user_to_domain(model) if model else None

    async def add(self, *, email: str, password_hash: str) -> User:
        model = UserModel(email=email, password_hash=password_hash)
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _user_to_domain(model)

    async def save(self, user: User) -> None:
        model = await self._session.get(UserModel, user.id)
        if model is None:
            raise ValueError(f"User {user.id} not found")
        model.email_verified_at = user.email_verified_at
        model.is_active = user.is_active
        model.anonymized_at = user.anonymized_at
        model.deleted_at = user.deleted_at
        await self._session.flush()


class VerificationTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_hash(self, token_hash: str) -> VerificationToken | None:
        stmt = select(VerificationTokenModel).where(VerificationTokenModel.token_hash == token_hash)
        model = await self._session.scalar(stmt)
        return _token_to_domain(model) if model else None

    async def get_latest_for_user(self, user_id: UUID) -> VerificationToken | None:
        stmt = (
            select(VerificationTokenModel)
            .where(VerificationTokenModel.user_id == user_id)
            .order_by(VerificationTokenModel.created_at.desc())
            .limit(1)
        )
        model = await self._session.scalar(stmt)
        return _token_to_domain(model) if model else None

    async def add(
        self, *, user_id: UUID, token_hash: str, expires_at: datetime
    ) -> VerificationToken:
        model = VerificationTokenModel(
            user_id=user_id, token_hash=token_hash, expires_at=expires_at
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _token_to_domain(model)

    async def save(self, token: VerificationToken) -> None:
        model = await self._session.get(VerificationTokenModel, token.id)
        if model is None:
            raise ValueError(f"VerificationToken {token.id} not found")
        model.used_at = token.used_at
        await self._session.flush()
