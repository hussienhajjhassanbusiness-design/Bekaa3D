from typing import Any

from arq.connections import RedisSettings

from app.core import models as _models  # noqa: F401 - registers models onto Base.metadata
from app.core.config import get_settings
from app.core.database import make_engine, make_session_factory
from app.core.logging import configure_logging
from app.jobs.registry import CRON_JOBS, FUNCTIONS


async def on_startup(ctx: dict[str, Any]) -> None:
    configure_logging()
    settings = get_settings()
    engine = make_engine(settings.database_url)
    ctx["engine"] = engine
    ctx["session_factory"] = make_session_factory(engine)


async def on_shutdown(ctx: dict[str, Any]) -> None:
    await ctx["engine"].dispose()


class WorkerSettings:
    # `functions` makes jobs directly enqueueable (tests, manual triggers);
    # `cron_jobs` (jobs/registry.py) gives each job its standing schedule.
    # arq's cron `unique=True` default means only one fires per tick even if
    # multiple worker replicas share this queue.
    functions = FUNCTIONS
    cron_jobs = CRON_JOBS
    on_startup = on_startup
    on_shutdown = on_shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
