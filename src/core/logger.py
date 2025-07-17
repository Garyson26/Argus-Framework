"""
Logging configuration for Argus.

Provides structured logging with Rich console output for beautiful CLI experience.
"""

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

from src.config import get_settings

# Custom theme for Argus
ARGUS_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "red bold",
        "critical": "red bold reverse",
        "success": "green bold",
        "debug": "dim",
        "scan.start": "blue bold",
        "scan.end": "green bold",
        "finding.critical": "red bold blink",
        "finding.high": "red",
        "finding.medium": "yellow",
        "finding.low": "cyan",
        "finding.info": "dim",
    }
)

# Global console instance
console = Console(theme=ARGUS_THEME, stderr=True)

# Logger cache
_loggers: dict[str, logging.Logger] = {}


def setup_logging(log_level: Optional[str] = None) -> None:
    """
    Setup logging for the application.
    
    Args:
        log_level: Override log level from settings
    """
    settings = get_settings()
    level = log_level or settings.log_level

    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                show_time=True,
                show_path=settings.debug,
                rich_tracebacks=True,
                tracebacks_show_locals=settings.debug,
                markup=True,
            )
        ],
    )

    # Reduce noise from third-party libraries
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("git").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """
    Get or create a logger with the given name.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger instance
    """
    if name not in _loggers:
        logger = logging.getLogger(name)
        _loggers[name] = logger
    return _loggers[name]


class ScanLogger:
    """
    Specialized logger for scan operations with progress tracking.
    
    Provides methods for logging scan events with appropriate styling.
    """

    def __init__(self, scan_type: str, target: str):
        self.scan_type = scan_type
        self.target = target
        self.logger = get_logger(f"argus.scanner.{scan_type}")

    def start(self) -> None:
        """Log scan start."""
        console.print(
            f"[scan.start]🔍 Starting {self.scan_type.upper()} scan on: {self.target}[/]"
        )

    def end(self, findings_count: int) -> None:
        """Log scan completion."""
        if findings_count == 0:
            console.print(f"[success]✅ {self.scan_type.upper()} scan completed - No issues found![/]")
        else:
            console.print(
                f"[scan.end]📋 {self.scan_type.upper()} scan completed - "
                f"Found {findings_count} issue(s)[/]"
            )

    def finding(self, severity: str, title: str, resource: Optional[str] = None) -> None:
        """Log a finding."""
        severity_lower = severity.lower()
        icon = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "⚡",
            "low": "📝",
            "info": "ℹ️",
        }.get(severity_lower, "📌")
        
        resource_text = f" ({resource})" if resource else ""
        console.print(f"[finding.{severity_lower}]{icon} [{severity.upper()}] {title}{resource_text}[/]")

    def error(self, message: str, exception: Optional[Exception] = None) -> None:
        """Log an error."""
        self.logger.error(message, exc_info=exception is not None)
        console.print(f"[error]❌ Error: {message}[/]")

    def warning(self, message: str) -> None:
        """Log a warning."""
        self.logger.warning(message)
        console.print(f"[warning]⚠️ Warning: {message}[/]")

    def info(self, message: str) -> None:
        """Log an info message."""
        self.logger.info(message)

    def debug(self, message: str) -> None:
        """Log a debug message."""
        self.logger.debug(message)

    def progress(self, current: int, total: int, message: str = "") -> None:
        """Log progress update."""
        percent = (current / total * 100) if total > 0 else 0
        console.print(f"[dim]📊 Progress: {current}/{total} ({percent:.1f}%) {message}[/]")
