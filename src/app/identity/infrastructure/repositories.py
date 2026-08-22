from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.identity.domain.entities import Session, User, VerificationToken
from app.identity.infrastructure.models import SessionModel, UserModel, VerificationTokenModel

# Naming note: `self._session` throughout this module is the SQLAlchemy
# AsyncSession (the unit of work). `Session` is our own login-session entity.
# Different things that unfortunately share a word.


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


def _session_to_domain(model: SessionModel) -> Session:
    return Session(
        id=model.id,
        user_id=model.user_id,
        refresh_token_hash=model.refresh_token_hash,
        token_version=model.token_version,
        expires_at=model.expires_at,
        last_used_at=model.last_used_at,
        rotated_at=model.rotated_at,
        revoked_at=model.revoked_at,
        reuse_detected_at=model.reuse_detected_at,
        ip_hash=model.ip_hash,
        user_agent=model.user_agent,
        created_at=model.created_at,
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


class SessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_for_update(self, session_id: UUID) -> Session | None:
        """Read one session row and hold a row lock until the transaction ends.

        `SELECT ... FOR UPDATE` is what makes rotation safe under concurrency:
        if the same refresh token is submitted twice at once, the second
        transaction blocks here until the first commits, then reads the
        *already rotated* row and correctly sees its own token as stale.
        Without the lock both would read version N, both would pass validation,
        and a replayed token would go undetected (FR-02: "when the same refresh
        token is submitted concurrently, at most one rotation succeeds")."""
        stmt = select(SessionModel).where(SessionModel.id == session_id).with_for_update()
        model = await self._session.scalar(stmt)
        return _session_to_domain(model) if model else None

    async def add(
        self,
        *,
        session_id: UUID,
        user_id: UUID,
        refresh_token_hash: str,
        expires_at: datetime,
        ip_hash: str | None,
        user_agent: str | None,
    ) -> Session:
        """The id is supplied by the caller rather than the database default,
        because the refresh token has to embed the session id *before* the row
        exists - the row stores that token's hash. Minting first and inserting
        once is simpler than inserting a placeholder and updating it."""
        model = SessionModel(
            id=session_id,
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            ip_hash=ip_hash,
            user_agent=user_agent,
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _session_to_domain(model)

    async def save(self, session: Session) -> None:
        # expires_at is deliberately absent: rotation does not extend a
        # session's lifetime, so a stolen-and-refreshed session still dies on
        # the original deadline (database-design.md 5.3 lists no expiry update).
        model = await self._session.get(SessionModel, session.id)
        if model is None:
            raise ValueError(f"Session {session.id} not found")
        model.refresh_token_hash = session.refresh_token_hash
        model.token_version = session.token_version
        model.last_used_at = session.last_used_at
        model.rotated_at = session.rotated_at
        model.revoked_at = session.revoked_at
        model.reuse_detected_at = session.reuse_detected_at
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
