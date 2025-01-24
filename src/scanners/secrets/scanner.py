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
    
