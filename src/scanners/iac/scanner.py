"""
Infrastructure as Code (IaC) scanner for Argus.

Scans Terraform, CloudFormation, Serverless, and Kubernetes manifests
for security misconfigurations using Checkov as the underlying engine.
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.config import get_settings
from src.core.exceptions import IaCScanError
from src.core.logger import ScanLogger, get_logger
from src.scanners.base import BaseScanner, Finding, Severity

logger = get_logger(__name__)


class IaCScanner(BaseScanner):
    """
    Infrastructure as Code scanner using Checkov.
    
    Supports:
    - Terraform (.tf, .tfvars)
    - CloudFormation (.json, .yaml, .yml, .template)
    - Serverless Framework (serverless.yml)
    - Kubernetes manifests (.yaml, .yml)
    """
    
    scanner_type = "iac"
    
    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        "terraform": [".tf", ".tf.json", ".tfvars"],
        "cloudformation": [".template", ".template.json", ".template.yaml"],
        "serverless": ["serverless.yml", "serverless.yaml"],
        "kubernetes": [],  # Detected by content
    }
    
    # Severity mapping from Checkov
    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "UNKNOWN": Severity.MEDIUM,
    }
    
    def __init__(
        self,
        framework: Optional[str] = None,
        skip_checks: Optional[list[str]] = None,
        custom_rules_path: Optional[str] = None,
        debug: bool = False,
    ):
        """
        Initialize the IaC scanner.
        
        Args:
            framework: IaC framework (auto-detect if None)
            skip_checks: Check IDs to skip
            custom_rules_path: Path to custom rules
            debug: Enable debug mode
        """
        super().__init__()
        
        settings = get_settings()
        
        self.framework = framework
        self.skip_checks = skip_checks or settings.iac_skip_checks
        self.custom_rules_path = custom_rules_path or settings.iac_custom_rules_path
        self.debug = debug or settings.debug
        
        self._scan_logger: Optional[ScanLogger] = None
        self._stats = {
            "files_scanned": 0,
            "checks_passed": 0,
            "checks_failed": 0,
            "checks_skipped": 0,
        }

    async def scan(self, target: str) -> dict[str, Any]:
        """
        Scan IaC files for security issues.
        
        Args:
            target: Path to IaC files or directory
            
        Returns:
            Dictionary containing scan results
        """
        started_at = datetime.now(timezone.utc)
        self.clear_findings()
        
        self._scan_logger = ScanLogger("iac", target)
        self._scan_logger.start()
        
        try:
            target_path = Path(target).resolve()
            
            if not target_path.exists():
                raise IaCScanError(f"Target path does not exist: {target}")
            
            # Detect framework if not specified
            framework = self.framework or self._detect_framework(target_path)
            self._debug_log(f"Using framework: {framework}")
            
            # Run Checkov
            checkov_results = await self._run_checkov(target_path, framework)
            
            # Parse results
            self._parse_checkov_results(checkov_results)
            
            # Create result
            result = self.create_result(
                target=str(target_path),
                started_at=started_at,
                metadata={
                    "framework": framework,
                    **self._stats,
                },
            )
            
            self._scan_logger.end(len(self._findings))
            return result.to_dict()
            
        except IaCScanError:
            raise
        except Exception as e:
            self._scan_logger.error(f"Scan failed: {e}", e)
            raise IaCScanError(f"IaC scan failed: {e}")

