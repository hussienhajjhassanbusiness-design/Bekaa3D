from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.identity.domain.entities import PasswordResetToken, Session, User, VerificationToken
from app.identity.infrastructure.models import (
    PasswordResetTokenModel,
    SessionModel,
    UserModel,
    VerificationTokenModel,
)

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


def _reset_token_to_domain(model: PasswordResetTokenModel) -> PasswordResetToken:
    return PasswordResetToken(
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
        # password_hash is written back because VS-004 lets a password change
        # after the row exists. `email` is still absent on purpose - changing an
        # address is a verification flow of its own, not a silent field update.
        model.password_hash = user.password_hash
        model.email_verified_at = user.email_verified_at
        model.is_active = user.is_active
        model.anonymized_at = user.anonymized_at
        model.deleted_at = user.deleted_at
        await self._session.flush()

    async def purge_never_verified_before(self, cutoff: datetime) -> int:
        """Physically delete accounts that were never verified and are older
        than `cutoff`. Returns how many went.

        FR-02 requires this ("Never-verified accounts are purged after the
        configured period") and database-design.md 5.1 explicitly permits a
        physical purge for this one case, in contrast to the anonymise-rather-
        than-delete rule that governs verified customers. The filter is
        `email_verified_at IS NULL`, so a verified account can never be caught
        by it regardless of age.

        Child rows go with the user through the schema's own foreign keys:
        verification_tokens, password_reset_tokens and sessions are ON DELETE
        CASCADE, while email_outbox and audit_logs are ON DELETE SET NULL so the
        delivery and audit history survives the account it referred to.
        """
        stmt = (
            delete(UserModel)
            .where(UserModel.email_verified_at.is_(None), UserModel.created_at < cutoff)
            .returning(UserModel.id)
        )
        purged_ids = (await self._session.scalars(stmt)).all()
        await self._session.flush()
        return len(purged_ids)


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

    async def revoke_all_for_user(self, *, user_id: UUID, at: datetime) -> int:
        """Revoke every live session this user has. Returns how many died.

        SEC-08 requires this on password change, and it is deliberately one
        UPDATE rather than a load-mutate-save loop over Session entities: the
        point of the operation is that no session survives it, and a loop leaves
        a window in which a session created after the read is missed. The
        `revoked_at IS NULL` filter makes it idempotent and keeps an earlier
        revocation timestamp - including a `reuse_detected_at` one - intact."""
        stmt = (
            update(SessionModel)
            .where(SessionModel.user_id == user_id, SessionModel.revoked_at.is_(None))
            .values(revoked_at=at)
            .returning(SessionModel.id)
        )
        revoked_ids = (await self._session.scalars(stmt)).all()
        await self._session.flush()
        return len(revoked_ids)


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


class PasswordResetTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_hash_for_update(self, token_hash: str) -> PasswordResetToken | None:
        """Read one reset token and hold a row lock until the transaction ends.

        Single-use is a business invariant, and an application-level `used_at IS
        NULL` check loses the race on its own: two requests carrying the same
        token would both read an unused row, both mark it used, and both replace
        the password. `SELECT ... FOR UPDATE` makes the second transaction block
        here and then re-read the row the first one already burned, so it
        correctly sees the token as spent. Same mechanism as
        SessionRepository.get_for_update, for the same reason."""
        stmt = (
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.token_hash == token_hash)
            .with_for_update()
        )
        model = await self._session.scalar(stmt)
        return _reset_token_to_domain(model) if model else None

    async def get_latest_for_user(self, user_id: UUID) -> PasswordResetToken | None:
        stmt = (
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user_id)
            .order_by(PasswordResetTokenModel.created_at.desc())
            .limit(1)
        )
        model = await self._session.scalar(stmt)
        return _reset_token_to_domain(model) if model else None

    async def add(
        self, *, user_id: UUID, token_hash: str, expires_at: datetime
    ) -> PasswordResetToken:
        model = PasswordResetTokenModel(
            user_id=user_id, token_hash=token_hash, expires_at=expires_at
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _reset_token_to_domain(model)

    async def save(self, token: PasswordResetToken) -> None:
        model = await self._session.get(PasswordResetTokenModel, token.id)
        if model is None:
            raise ValueError(f"PasswordResetToken {token.id} not found")
        model.used_at = token.used_at
        await self._session.flush()

    async def consume_outstanding_for_user(self, *, user_id: UUID, at: datetime) -> int:
        """Burn every unused reset token this user holds. Returns how many.

        Called after a successful reset. Without it, a second link the user
        requested earlier stays redeemable for the rest of its window, so an
        attacker who later reaches that older email can reset the password
        again - the account would be recoverable by someone who was never
        supposed to hold a live token. Same reasoning as revoking sessions:
        one successful reset must end every other route in."""
        stmt = (
            update(PasswordResetTokenModel)
            .where(
                PasswordResetTokenModel.user_id == user_id,
                PasswordResetTokenModel.used_at.is_(None),
            )
            .values(used_at=at)
            .returning(PasswordResetTokenModel.id)
        )
        consumed_ids = (await self._session.scalars(stmt)).all()
        await self._session.flush()
        return len(consumed_ids)
