from arq import cron
from arq.cron import CronJob
from arq.typing import WorkerCoroutine

from app.jobs.outbox import dispatch_outbox

FUNCTIONS: list[WorkerCoroutine] = [dispatch_outbox]

CRON_JOBS: list[CronJob] = [
    # Every minute, per SRS §23. run_at_startup catches up on anything queued
    # while the worker was down.
    cron(dispatch_outbox, second=0, run_at_startup=True),
]
