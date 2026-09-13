"""The sanctioned way to create an in-app notification.

Every other bounded context goes through this function. They must not import
`NotificationModel`, `NotificationRepository`, or write raw SQL against
`notifications` - that rule is what keeps Engagement's table Engagement's, and
`tests/unit/engagement/test_notification_boundary.py` enforces it.
"""

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.engagement.domain.entities import Notification
from app.engagement.domain.enums import NotificationType
from app.engagement.domain.exceptions import InvalidNotificationPayloadError
from app.engagement.domain.payload import validate_payload
from app.engagement.infrastructure.repositories import NotificationRepository


async def create_notification(
    session: AsyncSession,
    *,
    user_id: UUID,
    notification_type: NotificationType,
    payload: dict[str, Any],
) -> Notification:
    """Validate and insert one notification. Does **not** commit.

    The caller's `AsyncSession` is taken as an argument rather than opened here,
    which is the same shape VS-007's settings reader uses and it is the whole
    point of the port. A business event and the notification announcing it land
    in one transaction:

        business mutation
        create_notification(...)
        email outbox insert, if the event also warrants email
        COMMIT

    So if the payment rolls back, the notification announcing it rolls back
    with it, and no customer is ever told about something that did not happen.
    A service that opened its own session and committed could not offer that -
    it would commit the announcement of a change that was still able to fail.

    There is no message broker, no event bus and no background notification
    worker. An in-app notification is a row; once the transaction commits it is
    already delivered, because "delivery" here is the customer reading their own
    table. That is what distinguishes it from email, which leaves the system.
    """
    if not isinstance(notification_type, NotificationType):
        # Not a payload problem, so it does not go in the payload error: passing
        # a bare string here would otherwise reach asyncpg and fail as an opaque
        # enum bind error at flush time, a long way from the caller.
        raise InvalidNotificationPayloadError(
            [
                "notification_type must be a NotificationType, got "
                f"{type(notification_type).__name__}"
            ]
        )

    validated = validate_payload(payload)
    return await NotificationRepository(session).add(
        user_id=user_id,
        notification_type=notification_type,
        payload=validated,
    )
