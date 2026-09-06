from arq import cron
from arq.cron import CronJob
from arq.typing import WorkerCoroutine

from app.jobs.outbox import dispatch_outbox
from app.jobs.purge_unverified import purge_unverified_accounts

FUNCTIONS: list[WorkerCoroutine] = [dispatch_outbox, purge_unverified_accounts]

CRON_JOBS: list[CronJob] = [
    # Every minute, per SRS 23. run_at_startup catches up on anything queued
    # while the worker was down.
    cron(dispatch_outbox, second=0, run_at_startup=True),
    # Retention work, not user-facing: once a day, off the hour so it does not
    # contend with the minute-by-minute outbox sweep.
    cron(purge_unverified_accounts, hour=3, minute=17, second=0),
]
