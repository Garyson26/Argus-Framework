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

    def generate(
        self,
        scan_results: dict[str, Any],
        report_name: Optional[str] = None,
        formats: Optional[list[str]] = None,
    ) -> list[Path]:
        """
        Generate reports from scan results.
        
        Args:
            scan_results: Dictionary containing scan results
            report_name: Optional name for the report
            formats: List of formats to generate
            
        Returns:
            List of paths to generated reports
        """
        formats = formats or [self.report_format]
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_name = report_name or f"argus_report_{timestamp}"
        
        generated = []
        
        for fmt in formats:
            if fmt == "json":
                path = self._generate_json(scan_results, report_name)
            elif fmt == "markdown":
                path = self._generate_markdown(scan_results, report_name)
            elif fmt == "html":
                path = self._generate_html(scan_results, report_name)
            else:
                logger.warning(f"Unknown format: {fmt}")
                continue
            
            generated.append(path)
            logger.info(f"Generated report: {path}")
        
        return generated

