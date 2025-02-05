"""
Secret leak scanner for Argus.

Scans repositories and directories for hardcoded secrets, API keys,
and other sensitive credentials using pattern matching and entropy analysis.

Features:
- Parallel file scanning with asyncio
- Pattern-based detection with 50+ rules
- Shannon entropy analysis
- Git history scanning
- Progress tracking with Rich
"""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.config import get_settings
from src.core.exceptions import SecretScanError
from src.core.logger import ScanLogger, get_logger
from src.scanners.base import BaseScanner, Finding, Severity
from src.scanners.secrets.entropy import (
    calculate_confidence,
    calculate_entropy,
    find_high_entropy_strings,
    is_high_entropy,
)
from src.scanners.secrets.patterns import SecretPattern, SecretType, get_all_patterns
from src.utils.git_helper import GitHelper, scan_directory_files
from src.utils.progress import ScanProgress, BatchProcessor

logger = get_logger(__name__)

# Default batch size for parallel processing
DEFAULT_BATCH_SIZE = 50
DEFAULT_MAX_WORKERS = 10


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".swift", ".kt", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".config",
    ".tf", ".hcl", ".tfvars",
    ".sql", ".md", ".txt", ".rst",
    ".dockerfile", ".dockerignore",
    ".gitignore", ".npmrc", ".pypirc",
}

# Files to always scan regardless of extension
ALWAYS_SCAN_FILES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".env.local", ".env.production", ".env.development",
    "serverless.yml", "serverless.yaml",
    "config", "credentials", "secrets",
}

# Maximum file size to scan (10MB default)
MAX_FILE_SIZE = 10 * 1024 * 1024


class SecretScanner(BaseScanner):
    """
    Secret leak detection scanner.
    
    Scans files and git history for hardcoded secrets using:
    - Regex pattern matching for known secret formats
    - Shannon entropy analysis for high-entropy strings
    - Git history analysis for secrets in past commits
    """
    
    scanner_type = "secret"
    
    def __init__(
        self,
        scan_git_history: bool = True,
        max_commits: int = 1000,
        entropy_threshold: float = 4.5,
        patterns: Optional[list[SecretPattern]] = None,
        include_extensions: Optional[set[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
        debug: bool = False,
        parallel: bool = True,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_workers: int = DEFAULT_MAX_WORKERS,
        show_progress: bool = True,
    ):
        """
        Initialize the secret scanner.
        
        Args:
            scan_git_history: Whether to scan git commit history
            max_commits: Maximum number of commits to scan
            entropy_threshold: Threshold for high-entropy detection
            patterns: Custom patterns (defaults to all patterns)
            include_extensions: Additional file extensions to scan
            exclude_patterns: Patterns to exclude from scanning
            debug: Enable debug mode for verbose output
            parallel: Enable parallel file scanning (default: True)
            batch_size: Number of files to process per batch
            max_workers: Maximum concurrent workers
            show_progress: Show progress bar during scanning
        """
        super().__init__()
        
        settings = get_settings()
        
        self.scan_git_history = scan_git_history
        self.max_commits = max_commits
        self.entropy_threshold = entropy_threshold
        self.patterns = patterns or get_all_patterns()
        self.debug = debug or settings.debug
        
        # Parallel processing settings
        self.parallel = parallel
        self.batch_size = batch_size
        self.max_workers = max_workers
        self.show_progress = show_progress
        self._executor: Optional[ThreadPoolExecutor] = None
        self._progress: Optional[ScanProgress] = None
        
        # File extensions
        self.extensions = SCANNABLE_EXTENSIONS.copy()
        if include_extensions:
            self.extensions.update(include_extensions)
        
        # Exclude patterns
        self.exclude_patterns = exclude_patterns or [
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            ".tox",
            "dist",
            "build",
            ".idea",
            ".vscode",
        ]
        
        self._scan_logger: Optional[ScanLogger] = None
        self._stats = {
            "files_scanned": 0,
            "commits_scanned": 0,
            "patterns_checked": len(self.patterns),
            "bytes_scanned": 0,
        }
        self._lock = asyncio.Lock()

    async def scan(self, target: str) -> dict[str, Any]:
        """
        Scan a target path or repository for secrets.
        
        Args:
            target: Path to directory/repository or Git URL
            
        Returns:
            Dictionary containing scan results
        """
        started_at = datetime.utcnow()
        self.clear_findings()
        self._stats = {
            "files_scanned": 0,
            "commits_scanned": 0,
            "patterns_checked": len(self.patterns),
            "bytes_scanned": 0,
        }
        
        self._scan_logger = ScanLogger("secret", target)
        self._scan_logger.start()
        
        try:
            target_path = Path(target).resolve()
            
            if not target_path.exists():
                raise SecretScanError(f"Target path does not exist: {target}")
            
            # Check if it's a git repository
            git_helper = None
            if self._is_git_repo(target_path):
                git_helper = GitHelper(str(target_path))
                
                if self.scan_git_history:
                    self._debug_log(f"Scanning git history (max {self.max_commits} commits)")
                    await self._scan_git_history(git_helper)
            
            # Scan current files
            self._debug_log("Scanning current files")
            await self._scan_directory(target_path)
            
            # Create result
            result = self.create_result(
                target=str(target_path),
                started_at=started_at,
                metadata=self._stats,
            )
            
            self._scan_logger.end(len(self._findings))
            
            # Log findings summary
            self._log_findings_summary()
            
            return result.to_dict()
            
        except SecretScanError:
            raise
        except Exception as e:
            self._scan_logger.error(f"Scan failed: {e}", e)
            raise SecretScanError(f"Secret scan failed: {e}")

    def _is_git_repo(self, path: Path) -> bool:
        """Check if path is a git repository."""
        return (path / ".git").exists()

    def _debug_log(self, message: str) -> None:
        """Log debug message if debug mode is enabled."""
        if self.debug:
            logger.debug(f"[SECRET SCAN] {message}")

    async def _scan_git_history(self, git_helper: GitHelper) -> None:
        """Scan git commit history for secrets."""
        try:
            commit_count = 0
            
            for commit in git_helper.get_commits(max_commits=self.max_commits):
                commit_count += 1
                self._stats["commits_scanned"] = commit_count
                
                if commit_count % 100 == 0:
                    self._debug_log(f"Scanned {commit_count} commits...")
                
                # Get changed files in this commit
                changed_files = git_helper.get_changed_files(commit)
                
                for file_path in changed_files:
                    if not self._should_scan_file(file_path):
                        continue
                    
                    # Get file content at this commit
                    content = git_helper.get_file_at_commit(commit, file_path)
                    if content is None:
                        continue
                    
                    try:
                        text = content.decode('utf-8', errors='ignore')
                        await self._scan_content(
                            text,
                            file_path=file_path,
                            commit_hash=commit.hexsha,
                        )
                    except Exception as e:
                        self._debug_log(f"Error scanning {file_path} at {commit.hexsha[:7]}: {e}")
                        
        except Exception as e:
            self._scan_logger.warning(f"Git history scan error: {e}")

    async def _scan_directory(self, directory: Path) -> None:
        """
        Scan directory for secrets with parallel processing.
        
        Uses batch processing and concurrent execution for performance.
        """
        # Collect scannable files
        files_to_scan = []
        for file_path in directory.rglob("*"):
            if file_path.is_dir():
                continue
            if self._is_excluded(file_path):
                continue
            relative_path = str(file_path.relative_to(directory))
            if not self._should_scan_file(relative_path):
                continue
            try:
                file_size = file_path.stat().st_size
                if file_size > MAX_FILE_SIZE:
                    self._debug_log(f"Skipping large file: {relative_path} ({file_size} bytes)")
                    continue
            except OSError:
                continue
            files_to_scan.append((file_path, relative_path))
        
        total_files = len(files_to_scan)
        self._debug_log(f"Found {total_files} files to scan")
        
        if self.parallel and total_files > 1:
            await self._scan_files_parallel(files_to_scan, directory)
        else:
            await self._scan_files_sequential(files_to_scan)

