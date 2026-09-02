from collections.abc import Sequence
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.identity.domain.entities import (
    MfaCredential,
    MfaRecoveryCode,
    Session,
    User,
    VerificationToken,
)
from app.identity.domain.enums import MfaMethod
from app.identity.infrastructure.models import (
    MfaCredentialModel,
    MfaRecoveryCodeModel,
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


def _mfa_credential_to_domain(model: MfaCredentialModel) -> MfaCredential:
    return MfaCredential(
        id=model.id,
        user_id=model.user_id,
        method=model.method,
        secret_ciphertext=bytes(model.secret_ciphertext),
        enabled_at=model.enabled_at,
        last_used_at=model.last_used_at,
        last_totp_step=model.last_totp_step,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _mfa_recovery_code_to_domain(model: MfaRecoveryCodeModel) -> MfaRecoveryCode:
    return MfaRecoveryCode(
        id=model.id,
        mfa_credential_id=model.mfa_credential_id,
        code_hash=model.code_hash,
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


class MfaCredentialRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_user_id(self, user_id: UUID) -> MfaCredential | None:
        """Plain read, no lock. For callers that only ask a question - the
        login gate asking whether a challenge is needed, for instance. Locking
        there would serialise every administrator login for no benefit."""
        stmt = select(MfaCredentialModel).where(MfaCredentialModel.user_id == user_id)
        model = await self._session.scalar(stmt)
        return _mfa_credential_to_domain(model) if model else None

    async def get_by_user_id_for_update(self, user_id: UUID) -> MfaCredential | None:
        """Read the credential and hold a row lock until the transaction ends.

        Required by anything that decides *and then writes* `last_totp_step`.
        The replay check is a read-modify-write - read the mark, compare the
        matched step against it, write the new mark - and `max()` in the entity
        only orders values already in one process's memory. Two transactions
        that both read the same stale mark would both conclude the step was
        unspent, both accept, and one intercepted code would open two admin
        sessions. That is the exact failure the second factor exists to
        prevent, so the serialisation has to be in the database.

        With the lock the second transaction blocks here, then re-reads the row
        the first has already advanced and correctly finds the step spent.

        `populate_existing` matters: without it SQLAlchemy would hand back the
        instance already in this session's identity map and the post-lock
        re-read would silently return pre-lock data. Requests get a fresh
        session so the map is normally empty, but a guarantee that depends on
        that staying true is not a guarantee.

        Same idiom as `SessionRepository.get_for_update` and
        `MfaRecoveryCodeRepository.get_unused_by_hash`."""
        stmt = (
            select(MfaCredentialModel)
            .where(MfaCredentialModel.user_id == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        model = await self._session.scalar(stmt)
        return _mfa_credential_to_domain(model) if model else None

    async def add(
        self, *, user_id: UUID, method: MfaMethod, secret_ciphertext: bytes
    ) -> MfaCredential:
        model = MfaCredentialModel(
            user_id=user_id, method=method, secret_ciphertext=secret_ciphertext
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return _mfa_credential_to_domain(model)

    async def save(self, credential: MfaCredential) -> None:
        model = await self._session.get(MfaCredentialModel, credential.id)
        if model is None:
            raise ValueError(f"MfaCredential {credential.id} not found")
        model.secret_ciphertext = credential.secret_ciphertext
        model.enabled_at = credential.enabled_at
        model.last_used_at = credential.last_used_at
        model.last_totp_step = credential.last_totp_step
        await self._session.flush()


class MfaRecoveryCodeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_unused_by_hash(
        self, *, mfa_credential_id: UUID, code_hash: str
    ) -> MfaRecoveryCode | None:
        """Find one unused code and hold a row lock until the transaction ends.

        `SELECT ... FOR UPDATE` is what actually makes a recovery code
        one-time-use. Without it, two requests submitting the same code
        concurrently both read `used_at IS NULL`, both pass the domain guard in
        MfaRecoveryCode.redeem, and the code is spent twice - which for a
        recovery credential means two admin sessions from one stolen code. With
        the lock, the second transaction blocks here, then re-reads the row the
        first already marked used and correctly finds nothing."""
        stmt = (
            select(MfaRecoveryCodeModel)
            .where(
                MfaRecoveryCodeModel.mfa_credential_id == mfa_credential_id,
                MfaRecoveryCodeModel.code_hash == code_hash,
                MfaRecoveryCodeModel.used_at.is_(None),
            )
            .with_for_update()
        )
        model = await self._session.scalar(stmt)
        return _mfa_recovery_code_to_domain(model) if model else None

    async def add_set(
        self, *, mfa_credential_id: UUID, code_hashes: Sequence[str]
    ) -> list[MfaRecoveryCode]:
        models = [
            MfaRecoveryCodeModel(mfa_credential_id=mfa_credential_id, code_hash=code_hash)
            for code_hash in code_hashes
        ]
        self._session.add_all(models)
        await self._session.flush()
        for model in models:
            await self._session.refresh(model)
        return [_mfa_recovery_code_to_domain(model) for model in models]

    async def count_unused(self, mfa_credential_id: UUID) -> int:
        stmt = (
            select(func.count())
            .select_from(MfaRecoveryCodeModel)
            .where(
                MfaRecoveryCodeModel.mfa_credential_id == mfa_credential_id,
                MfaRecoveryCodeModel.used_at.is_(None),
            )
        )
        return (await self._session.scalar(stmt)) or 0

    async def delete_unused(self, mfa_credential_id: UUID) -> int:
        """Wipe the unused half of a code set, for regeneration.

        Only unused rows are removed. Spent codes stay, because `code_hash` is
        UNIQUE table-wide and deleting the evidence that a code was already
        redeemed would let the identical string be issued again later and
        accepted a second time. Deletion rather than soft-delete is what
        database-design.md 5.7 calls for ("invalidates/removes prior unused code
        set"), and these rows carry no audit value - the regeneration event
        itself is what gets audited."""
        stmt = (
            delete(MfaRecoveryCodeModel)
            .where(
                MfaRecoveryCodeModel.mfa_credential_id == mfa_credential_id,
                MfaRecoveryCodeModel.used_at.is_(None),
            )
            .execution_options(synchronize_session=False)
        )
        # execute() is typed as returning Result; rowcount is a CursorResult
        # attribute, and a DML statement always produces one.
        result = cast("CursorResult[Any]", await self._session.execute(stmt))
        return result.rowcount

    async def save(self, code: MfaRecoveryCode) -> None:
        model = await self._session.get(MfaRecoveryCodeModel, code.id)
        if model is None:
            raise ValueError(f"MfaRecoveryCode {code.id} not found")
        model.used_at = code.used_at
        await self._session.flush()
