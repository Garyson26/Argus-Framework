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
    
    Args:
        target_path: Path to scan for secrets
        scan_git_history: Whether to scan git history
        max_commits: Maximum commits to scan
        entropy_threshold: Entropy threshold for detection
        
    Returns:
        Scan results dictionary
    """
    from src.scanners.secrets.scanner import SecretScanner
    
    self.update_state(state="SCANNING", meta={"target": target_path})
    
    scanner = SecretScanner(
        scan_git_history=scan_git_history,
        max_commits=max_commits,
        entropy_threshold=entropy_threshold,
    )
    
    result = run_async(scanner.scan(target_path))
    return result


@celery_app.task(bind=True, name="argus.tasks.cloud_scan")
def run_cloud_scan(
    self,
    profile: str = None,
    regions: list[str] = None,
    services: list[str] = None,
) -> dict[str, Any]:
    """
    Run AWS cloud scan as async task.
    
    Args:
        profile: AWS profile name
        regions: List of regions to scan
        services: List of services to scan
        
    Returns:
        Scan results dictionary
    """
    from src.scanners.aws_cloud.scanner import AWSCloudScanner
    
    self.update_state(state="SCANNING", meta={"profile": profile or "default"})
    
    scanner = AWSCloudScanner(
        profile=profile,
        regions=regions,
        services=services,
    )
    
    result = run_async(scanner.scan())
    return result


@celery_app.task(bind=True, name="argus.tasks.iac_scan")
def run_iac_scan(
    self,
    target_path: str,
    framework: str = None,
    skip_checks: list[str] = None,
) -> dict[str, Any]:
    """
    Run IaC scan as async task.
    
    Args:
        target_path: Path to IaC files
        framework: IaC framework
        skip_checks: Checks to skip
        
    Returns:
        Scan results dictionary
    """
    from src.scanners.iac.scanner import IaCSCanner
    
    self.update_state(state="SCANNING", meta={"target": target_path})
    
    scanner = IaCSCanner(
        framework=framework,
        skip_checks=skip_checks,
    )
    
    result = run_async(scanner.scan(target_path))
    return result


@celery_app.task(bind=True, name="argus.tasks.iam_analyze")
def run_iam_analysis(
    self,
    profile: str = None,
    check_escalation: bool = True,
    check_unused: bool = True,
) -> dict[str, Any]:
    """
    Run IAM analysis as async task.
    
    Args:
        profile: AWS profile name
        check_escalation: Check for escalation paths
        check_unused: Check for unused permissions
        
    Returns:
        Analysis results dictionary
    """
    from src.scanners.iam_analyzer.analyzer import IAMAnalyzer
    
    self.update_state(state="ANALYZING", meta={"profile": profile or "default"})
    
    analyzer = IAMAnalyzer(
        profile=profile,
        check_escalation=check_escalation,
        check_unused=check_unused,
    )
    
    result = run_async(analyzer.analyze())
    return result
