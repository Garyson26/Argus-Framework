"""
Progress tracking utilities for FuFuFaFa.

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

    def update(
        self,
        name: str,
        advance: int = 1,
        description: Optional[str] = None,
        total: Optional[int] = None,
    ) -> None:
        """
        Update task progress.
        
        Args:
            name: Task identifier
            advance: Number of items completed
            description: Update description text
            total: Update total count
        """
        if name not in self._tasks:
            return
            
        task_id = self._tasks[name]
        update_kwargs: dict[str, Any] = {"advance": advance}
        
        if description:
            update_kwargs["description"] = description
        if total is not None:
            update_kwargs["total"] = total
            
        self._progress.update(task_id, **update_kwargs)

    def complete_task(self, name: str) -> None:
        """Mark a task as complete."""
        if name in self._tasks:
            task_id = self._tasks[name]
            self._progress.update(task_id, completed=True)

    def add_finding(self, severity: str) -> None:
        """
        Increment finding counter by severity.
        
        Args:
            severity: Finding severity level
        """
        severity_lower = severity.lower()
        if severity_lower == "critical":
            self._critical_count += 1
        elif severity_lower == "high":
            self._high_count += 1
        elif severity_lower == "medium":
            self._medium_count += 1
        elif severity_lower == "low":
            self._low_count += 1
        else:
            self._info_count += 1

    def get_summary_table(self) -> Table:
        """Create a summary table of findings by severity."""
        table = Table(title="Scan Summary", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        if self._critical_count:
            table.add_row("[red]Critical[/red]", str(self._critical_count))
        if self._high_count:
            table.add_row("[orange1]High[/orange1]", str(self._high_count))
        if self._medium_count:
            table.add_row("[yellow]Medium[/yellow]", str(self._medium_count))
        if self._low_count:
            table.add_row("[blue]Low[/blue]", str(self._low_count))
        if self._info_count:
            table.add_row("[dim]Info[/dim]", str(self._info_count))
            
        total = (
            self._critical_count + self._high_count + 
            self._medium_count + self._low_count + self._info_count
        )
        table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")
        
        return table

    def print_summary(self) -> None:
        """Print the findings summary table."""
        console.print(self.get_summary_table())


@contextmanager
def scan_progress(
    description: str = "Scanning",
    total: Optional[int] = None,
) -> Generator[ScanProgress, None, None]:
    """
    Context manager for simple progress tracking.
    
    Args:
        description: Progress bar description
        total: Total items to scan
        
    Yields:
        ScanProgress instance
        
    Example:
        with scan_progress("Scanning files", total=100) as progress:
            for file in files:
                # ... process file ...
                progress.update("main", advance=1)
    """
    tracker = ScanProgress(description=description)
    with tracker:
        tracker.add_task("main", total=total, description=description)
        yield tracker


class BatchProcessor:
    """
    Batch processor for efficient parallel operations.
    
    Divides work into batches for concurrent processing while
    respecting memory limits.
    """

    def __init__(
        self,
        batch_size: int = 50,
        max_concurrent: int = 10,
    ):
        """
        Initialize batch processor.
        
        Args:
            batch_size: Number of items per batch
            max_concurrent: Maximum concurrent batches
        """
        self.batch_size = batch_size
        self.max_concurrent = max_concurrent

    def batch(self, items: list) -> Generator[list, None, None]:
        """
        Yield batches of items.
        
        Args:
            items: List of items to batch
            
        Yields:
            Batches of items
        """
        for i in range(0, len(items), self.batch_size):
            yield items[i:i + self.batch_size]

    async def process_batches(
        self,
        items: list,
        processor,
        progress: Optional[ScanProgress] = None,
        task_name: str = "main",
    ):
        """
        Process items in parallel batches.
        
        Args:
            items: Items to process
            processor: Async function to process each item
            progress: Optional progress tracker
            task_name: Progress task name
        """
        import asyncio
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def process_with_semaphore(item):
            async with semaphore:
                result = await processor(item)
                if progress:
                    progress.update(task_name, advance=1)
                return result
        
        tasks = [process_with_semaphore(item) for item in items]
        return await asyncio.gather(*tasks, return_exceptions=True)


def print_banner(text: str, style: str = "bold blue") -> None:
    """Print a styled banner."""
    console.print(f"\n[{style}]{'─' * 60}[/{style}]")
    console.print(f"[{style}] {text}[/{style}]")
    console.print(f"[{style}]{'─' * 60}[/{style}]\n")


def print_finding(
    title: str,
    severity: str,
    resource: Optional[str] = None,
    description: Optional[str] = None,
) -> None:
    """
    Print a finding in a formatted style.
    
    Args:
        title: Finding title
        severity: Severity level
        resource: Affected resource
        description: Finding description
    """
    severity_colors = {
        "critical": "red bold",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    
    color = severity_colors.get(severity.lower(), "white")
    
    console.print(f"  [{color}]● {severity.upper()}[/{color}] {title}")
    if resource:
        console.print(f"    [dim]Resource:[/dim] {resource}")
    if description:
        console.print(f"    [dim]{description}[/dim]")
