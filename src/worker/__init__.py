"""Worker module for Celery tasks."""

from src.worker.tasks import celery_app

__all__ = ["celery_app"]
