"""
Git helper utilities for Argus.

Provides repository cloning, commit history traversal, and file content extraction.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Generator, Optional
from urllib.parse import urlparse

from git import Commit, Repo
from git.exc import GitCommandError, InvalidGitRepositoryError

from src.core.exceptions import GitError
from src.core.logger import get_logger

logger = get_logger(__name__)


class GitHelper:
    """
    Git repository helper for secret scanning.
    
    Provides methods for:
    - Cloning repositories (public/private)
    - Traversing commit history
    - Extracting file contents at specific commits
    """

    def __init__(
        self,
        path: str,
        clone_if_url: bool = True,
        auth_token: Optional[str] = None,
    ):
        """
        Initialize GitHelper.
        
        Args:
            path: Local path or Git URL
            clone_if_url: Whether to clone if path is a URL
            auth_token: OAuth/PAT token for private repos
        """
        self.original_path = path
        self.auth_token = auth_token
        self._temp_dir: Optional[str] = None
        self._repo: Optional[Repo] = None
        
        if self._is_git_url(path) and clone_if_url:
            self.path = self._clone_repo(path)
        else:
            self.path = path

    def _is_git_url(self, path: str) -> bool:
        """Check if path is a Git URL."""
        try:
            parsed = urlparse(path)
            return parsed.scheme in ("http", "https", "git", "ssh") or path.endswith(".git")
        except Exception:
            return False

    def _clone_repo(self, url: str) -> str:
        """
        Clone a Git repository to a temporary directory.
        
        Args:
            url: Git repository URL
            
        Returns:
            Path to cloned repository
        """
        self._temp_dir = tempfile.mkdtemp(prefix="argus_")
        
        # Inject auth token if provided
        clone_url = url
        if self.auth_token:
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https"):
                clone_url = f"{parsed.scheme}://{self.auth_token}@{parsed.netloc}{parsed.path}"
        
        try:
            logger.info(f"Cloning repository: {url}")
            Repo.clone_from(clone_url, self._temp_dir, depth=None)
            return self._temp_dir
        except GitCommandError as e:
            self.cleanup()
            raise GitError(
                f"Failed to clone repository: {e}",
                repository=url,
            )

    @property
    def repo(self) -> Repo:
        """Get the Git repository object."""
        if self._repo is None:
            try:
                self._repo = Repo(self.path)
            except InvalidGitRepositoryError:
                raise GitError(
                    f"Not a valid Git repository: {self.path}",
                    repository=self.path,
                )
        return self._repo

    def is_git_repo(self) -> bool:
        """Check if the path is a valid Git repository."""
        try:
            _ = self.repo
            return True
        except GitError:
            return False

    def get_commits(
        self,
        max_commits: int = 1000,
        branch: Optional[str] = None,
    ) -> Generator[Commit, None, None]:
        """
        Get commits from the repository.
        
        Args:
            max_commits: Maximum number of commits to retrieve
            branch: Branch to get commits from (default: current)
            
        Yields:
            Git Commit objects
        """
        try:
            if branch:
                commits = self.repo.iter_commits(branch, max_count=max_commits)
            else:
                commits = self.repo.iter_commits(max_count=max_commits)
            
            yield from commits
        except GitCommandError as e:
            raise GitError(
                f"Failed to get commits: {e}",
                repository=self.path,
            )

    def get_file_at_commit(
        self,
        commit: Commit,
        file_path: str,
    ) -> Optional[bytes]:
        """
        Get file content at a specific commit.
        
        Args:
            commit: Git Commit object
            file_path: Relative path to file in repo
            
        Returns:
            File content as bytes, or None if file doesn't exist
        """
        try:
            blob = commit.tree / file_path
            return blob.data_stream.read()
        except KeyError:
            # File doesn't exist at this commit
            return None
        except Exception as e:
            logger.debug(f"Failed to get file {file_path} at commit {commit.hexsha}: {e}")
            return None

    def get_changed_files(self, commit: Commit) -> list[str]:
        """
        Get list of files changed in a commit.
        
        Args:
            commit: Git Commit object
            
        Returns:
            List of changed file paths
        """
        changed_files = []
        
        try:
            if commit.parents:
                # Compare with parent commit
                parent = commit.parents[0]
                diff = parent.diff(commit)
                
                for change in diff:
                    if change.a_path:
                        changed_files.append(change.a_path)
                    if change.b_path and change.b_path != change.a_path:
                        changed_files.append(change.b_path)
            else:
                # Initial commit - all files are new
                changed_files = [
                    item.path for item in commit.tree.traverse()
                    if item.type == "blob"
                ]
        except Exception as e:
            logger.debug(f"Failed to get changed files for commit {commit.hexsha}: {e}")
        
        return changed_files

    def get_all_files(self, commit: Optional[Commit] = None) -> Generator[tuple[str, bytes], None, None]:
        """
        Get all files in the repository at a specific commit.
        
        Args:
            commit: Commit to get files from (default: HEAD)
            
        Yields:
            Tuples of (file_path, content)
        """
        if commit is None:
            commit = self.repo.head.commit
        
        try:
            for item in commit.tree.traverse():
                if item.type == "blob":
                    try:
                        content = item.data_stream.read()
                        yield item.path, content
                    except Exception as e:
                        logger.debug(f"Failed to read file {item.path}: {e}")
        except Exception as e:
            raise GitError(
                f"Failed to traverse repository: {e}",
                repository=self.path,
            )

    def get_branches(self) -> list[str]:
        """Get list of branch names."""
        return [ref.name for ref in self.repo.refs if ref.name.startswith("origin/")]

    def get_current_branch(self) -> str:
        """Get current branch name."""
        try:
            return self.repo.active_branch.name
        except TypeError:
            # Detached HEAD state
            return self.repo.head.commit.hexsha[:7]

    def cleanup(self) -> None:
        """Clean up temporary directory if created."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir)
                self._temp_dir = None
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary directory: {e}")

    def __enter__(self) -> "GitHelper":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def __del__(self) -> None:
        self.cleanup()


def scan_directory_files(
    directory: str,
    extensions: Optional[list[str]] = None,
    ignore_patterns: Optional[list[str]] = None,
) -> Generator[tuple[str, bytes], None, None]:
    """
    Scan a directory for files (non-Git approach).
    
    Args:
        directory: Directory path to scan
        extensions: File extensions to include (e.g., ['.py', '.js'])
        ignore_patterns: Patterns to ignore (e.g., ['node_modules', '.git'])
        
    Yields:
        Tuples of (file_path, content)
    """
    ignore_patterns = ignore_patterns or [
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        "dist",
        "build",
        "*.pyc",
        "*.pyo",
        "*.so",
        "*.dylib",
    ]
    
    root_path = Path(directory)
    
    for file_path in root_path.rglob("*"):
        # Skip directories
        if file_path.is_dir():
            continue
        
        # Check ignore patterns
        relative_path = str(file_path.relative_to(root_path))
        should_ignore = any(
            pattern in relative_path or file_path.match(pattern)
            for pattern in ignore_patterns
        )
        
        if should_ignore:
            continue
        
        # Check extensions if specified
        if extensions:
            if file_path.suffix.lower() not in extensions:
                continue
        
        # Try to read file
        try:
            content = file_path.read_bytes()
            yield relative_path, content
        except (IOError, OSError) as e:
            logger.debug(f"Failed to read file {file_path}: {e}")
