"""
Secret leak scanner for FuFuFaFa.

Scans repositories and directories for hardcoded secrets, API keys,
and other sensitive credentials using pattern matching and entropy analysis.
"""

import os
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

logger = get_logger(__name__)


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
        """
        super().__init__()
        
        settings = get_settings()
        
        self.scan_git_history = scan_git_history
        self.max_commits = max_commits
        self.entropy_threshold = entropy_threshold
        self.patterns = patterns or get_all_patterns()
        self.debug = debug or settings.debug
        
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
        """Scan directory for secrets."""
        for file_path in directory.rglob("*"):
            # Skip directories
            if file_path.is_dir():
                continue
            
            # Skip excluded patterns
            if self._is_excluded(file_path):
                continue
            
            # Check if file should be scanned
            relative_path = str(file_path.relative_to(directory))
            if not self._should_scan_file(relative_path):
                continue
            
            # Check file size
            try:
                file_size = file_path.stat().st_size
                if file_size > MAX_FILE_SIZE:
                    self._debug_log(f"Skipping large file: {relative_path} ({file_size} bytes)")
                    continue
            except OSError:
                continue
            
            # Read and scan file
            try:
                content = file_path.read_bytes()
                self._stats["bytes_scanned"] += len(content)
                self._stats["files_scanned"] += 1
                
                text = content.decode('utf-8', errors='ignore')
                await self._scan_content(text, file_path=relative_path)
                
            except Exception as e:
                self._debug_log(f"Error scanning {relative_path}: {e}")

    def _should_scan_file(self, file_path: str) -> bool:
        """Check if a file should be scanned based on extension/name."""
        path = Path(file_path)
        
        # Always scan certain files
        if path.name.lower() in ALWAYS_SCAN_FILES:
            return True
        
        # Check extension
        return path.suffix.lower() in self.extensions

    def _is_excluded(self, file_path: Path) -> bool:
        """Check if file path matches any exclude pattern."""
        path_str = str(file_path)
        return any(pattern in path_str for pattern in self.exclude_patterns)

    async def _scan_content(
        self,
        content: str,
        file_path: str,
        commit_hash: Optional[str] = None,
    ) -> None:
        """
        Scan content for secrets.
        
        Args:
            content: File content to scan
            file_path: Path to the file
            commit_hash: Git commit hash (if from history)
        """
        lines = content.split('\n')
        
        # Scan with pattern matching
        for pattern in self.patterns:
            matches = pattern.match(content)
            
            for match in matches:
                # Find line number
                line_number = content[:match.start()].count('\n') + 1
                
                # Create finding
                finding = Finding(
                    rule_id=f"SECRET-{pattern.secret_type.value.upper()}",
                    severity=pattern.severity,
                    title=pattern.name,
                    description=pattern.description,
                    file_path=file_path,
                    line_number=line_number,
                    commit_hash=commit_hash,
                    suggestion=pattern.suggestion,
                    confidence=pattern.confidence,
                    metadata={
                        "secret_type": pattern.secret_type.value,
                        "matched_value": self._mask_secret(match.group()),
                        "line_content": self._get_line_context(lines, line_number),
                    },
                )
                
                self.add_finding(finding)
                self._scan_logger.finding(
                    pattern.severity.value,
                    pattern.name,
                    file_path,
                )
        
        # Scan with entropy detection
        high_entropy_strings = find_high_entropy_strings(
            content,
            threshold=self.entropy_threshold,
        )
        
        for item in high_entropy_strings:
            # Skip if already matched by a pattern
            if self._is_pattern_match(item['value']):
                continue
            
            # Find line number
            line_number = content[:item['start']].count('\n') + 1
            confidence = calculate_confidence(item['entropy'], self.entropy_threshold)
            
            finding = Finding(
                rule_id="SECRET-HIGH-ENTROPY",
                severity=Severity.MEDIUM,
                title="High Entropy String Detected",
                description="A high-entropy string was detected that may be a secret",
                file_path=file_path,
                line_number=line_number,
                commit_hash=commit_hash,
                suggestion="Review this string to determine if it's a hardcoded secret",
                confidence=confidence,
                metadata={
                    "secret_type": SecretType.HIGH_ENTROPY.value,
                    "entropy": item['entropy'],
                    "matched_value": self._mask_secret(item['value']),
                    "line_content": self._get_line_context(lines, line_number),
                },
            )
            
            self.add_finding(finding)

    def _is_pattern_match(self, value: str) -> bool:
        """Check if value matches any existing finding."""
        for finding in self._findings:
            if finding.metadata.get("matched_value") == self._mask_secret(value):
                return True
        return False

    def _mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask a secret value for safe display."""
        if len(secret) <= visible_chars * 2:
            return "*" * len(secret)
        return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]

    def _get_line_context(self, lines: list[str], line_number: int, context: int = 0) -> str:
        """Get line content with optional surrounding context."""
        if line_number < 1 or line_number > len(lines):
            return ""
        
        if context == 0:
            return lines[line_number - 1].strip()
        
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        
        return "\n".join(lines[start:end])

    def _log_findings_summary(self) -> None:
        """Log summary of findings."""
        if not self._findings:
            return
        
        # Group by secret type
        by_type = {}
        for finding in self._findings:
            secret_type = finding.metadata.get("secret_type", "unknown")
            by_type[secret_type] = by_type.get(secret_type, 0) + 1
        
        self._debug_log(f"Findings by type: {by_type}")
        self._debug_log(f"Stats: {self._stats}")
