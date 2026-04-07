"""
Celery task definitions for Argus.

Provides async task execution for long-running scans.
"""

import asyncio
from typing import Any

from celery import Celery

from src.config import get_settings

settings = get_settings()

# Initialize Celery
celery_app = Celery(
    "argus",
    broker=settings.celery_broker,
    backend=settings.celery_backend,
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    task_soft_time_limit=3300,  # 55 minutes
    worker_prefetch_multiplier=1,
    worker_concurrency=4,
)


def run_async(coro):
    """Helper to run async functions in Celery tasks."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True, name="argus.tasks.secret_scan")
def run_secret_scan(
    self,
    target_path: str,
    scan_git_history: bool = True,
    max_commits: int = 1000,
    entropy_threshold: float = 4.5,
) -> dict[str, Any]:
    """
    Run secret scan as async task.
    
