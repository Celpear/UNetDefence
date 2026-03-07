"""Scheduler process: run aggregation and baseline jobs on a schedule."""

import asyncio
import logging
import sys

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from unetdefence.config import get_settings
from unetdefence.scheduler.jobs import run_aggregation_5m, run_daily_baselines
from unetdefence.storage import init_pool, close_pool

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(
        level=get_settings().log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )

    async def start_scheduler() -> None:
        await init_pool()
        scheduler = AsyncIOScheduler()
        scheduler.add_job(run_aggregation_5m, "interval", minutes=5, id="agg_5m")
        scheduler.add_job(run_daily_baselines, "cron", hour=1, minute=0, id="baselines")
        scheduler.start()
        logger.info("Scheduler started (5m aggregation, daily baselines)")
        try:
            while True:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            pass
        finally:
            scheduler.shutdown(wait=False)
            await close_pool()

    try:
        asyncio.run(start_scheduler())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
