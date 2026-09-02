"""outbox attempt_count check, verification token expiry index, payload redaction

Revision ID: 7b1e04c9d2a5
Revises: 455cbf96ab6f
Create Date: 2026-08-30 09:40:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7b1e04c9d2a5"
down_revision: str | None = "455cbf96ab6f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # database-design.md 13.3 specifies CHECK >= 0 on attempt_count; the VS-002
    # migration created the column without it.
    op.create_check_constraint(
        "ck_email_outbox_attempt_count_non_negative", "email_outbox", "attempt_count >= 0"
    )

    # database-design.md 19.11 lists verification_tokens(expires_at) for the
    # retention purge; the VS-002 migration omitted it.
    op.create_index(
        "ix_verification_tokens_expires_at_live",
        "verification_tokens",
        ["expires_at"],
        unique=False,
        postgresql_where=sa.text("used_at IS NULL"),
    )

    # One-off backfill. Rows written before payload redaction still hold the raw
    # verification/reset token in plaintext, and those tokens stay redeemable
    # until they expire - the exposure this release closes going forward is
    # already sitting in the table. Values are replaced, keys kept, matching
    # EmailOutboxMessage._redact_payload.
    #
    # Deliberately NOT reversed in downgrade(): the plaintext is gone and cannot
    # be reconstructed. Downgrading the schema does not, and must not, put
    # redeemable secrets back.
    op.execute(
        """
        UPDATE email_outbox
        SET payload = (
            SELECT jsonb_object_agg(key, '"[redacted]"'::jsonb)
            FROM jsonb_object_keys(payload) AS key
        )
        WHERE status IN ('sent', 'failed')
          AND payload <> '{}'::jsonb
          AND EXISTS (
              SELECT 1 FROM jsonb_each_text(payload) AS kv
              WHERE kv.value <> '[redacted]'
          )
        """
    )


def downgrade() -> None:
    op.drop_index(
        "ix_verification_tokens_expires_at_live",
        table_name="verification_tokens",
        postgresql_where=sa.text("used_at IS NULL"),
    )
    op.drop_constraint("ck_email_outbox_attempt_count_non_negative", "email_outbox", type_="check")
