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

