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


