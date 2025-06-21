"""
Progress tracking utilities for Argus.

Provides Rich-based progress bars and concurrent task tracking for scans.
"""

from contextlib import contextmanager
from typing import Any, Generator, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

console = Console()


class ScanProgress:
    """
    Unified progress tracker for all scanners.
    
    Features:
    - Multiple concurrent task tracking
    - Real-time ETA estimation
    - Severity counters
    - Memory-efficient streaming updates
    """

    def __init__(
        self,
        description: str = "Scanning",
        show_speed: bool = True,
        transient: bool = False,
    ):
        """
        Initialize scan progress tracker.
        
        Args:
            description: Main task description
            show_speed: Show items/second speed
            transient: Clear progress bar on completion
        """
        self.description = description
        self.transient = transient
        
        # Severity counters
        self._critical_count = 0
        self._high_count = 0
        self._medium_count = 0
        self._low_count = 0
        self._info_count = 0
        
        # Build progress columns
        columns = [
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
        ]
        
        if show_speed:
            columns.append(TextColumn("[cyan]{task.speed} items/s"))
        
        self._progress = Progress(
            *columns,
            console=console,
            transient=transient,
            expand=False,
        )
        
        self._tasks: dict[str, TaskID] = {}
        self._started = False

    def __enter__(self) -> "ScanProgress":
        """Start the progress display."""
        self._progress.start()
        self._started = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Stop the progress display."""
        self._progress.stop()
        self._started = False

    def add_task(
        self,
        name: str,
        total: Optional[int] = None,
        description: Optional[str] = None,
    ) -> TaskID:
        """
        Add a new task to track.
        
        Args:
            name: Unique task identifier
            total: Total items to process (None for indeterminate)
            description: Display description
            
        Returns:
            Task ID for updates
        """
        desc = description or name
        task_id = self._progress.add_task(
            desc,
            total=total if total is not None else 100,
            start=total is not None,
        )
        self._tasks[name] = task_id
        return task_id

