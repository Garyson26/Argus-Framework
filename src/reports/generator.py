"""
Report generator for Argus.

Generates comprehensive security audit reports in multiple formats:
- JSON (machine-readable)
- Markdown (documentation)
- HTML (visual reports)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.config import get_settings
from src.core.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """
    Security report generator.
    
