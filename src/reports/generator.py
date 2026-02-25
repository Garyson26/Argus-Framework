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
    
    Generates reports from scan results in various formats with
    executive summaries, detailed findings, and remediation guidance.
    """
    
    def __init__(
        self,
        output_dir: Optional[str] = None,
        report_format: Optional[str] = None,
    ):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to save reports
            report_format: Default format (json, markdown, html)
        """
        settings = get_settings()
        
        self.output_dir = Path(output_dir or settings.report_output_dir)
        self.report_format = report_format or settings.report_format
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

