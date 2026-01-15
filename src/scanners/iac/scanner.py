"""
Infrastructure as Code (IaC) scanner for FuFuFaFa.

Scans Terraform, CloudFormation, Serverless, and Kubernetes manifests
for security misconfigurations using Checkov as the underlying engine.
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.config import get_settings
from src.core.exceptions import IaCScanError
from src.core.logger import ScanLogger, get_logger
from src.scanners.base import BaseScanner, Finding, Severity

logger = get_logger(__name__)


class IaCSCanner(BaseScanner):
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
        started_at = datetime.utcnow()
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

    def _debug_log(self, message: str) -> None:
        """Log debug message if debug mode enabled."""
        if self.debug:
            logger.debug(f"[IAC SCAN] {message}")

    def _detect_framework(self, path: Path) -> str:
        """Detect IaC framework from file contents."""
        if path.is_file():
            file_name = path.name.lower()
            
            # Check by filename
            if file_name in ("serverless.yml", "serverless.yaml"):
                return "serverless"
            
            # Check by extension
            for framework, extensions in self.FRAMEWORK_PATTERNS.items():
                if any(file_name.endswith(ext) for ext in extensions):
                    return framework
            
            # Check content for Kubernetes
            try:
                content = path.read_text()
                if "apiVersion:" in content and "kind:" in content:
                    return "kubernetes"
            except Exception:
                pass
            
            return "terraform"  # Default
        
        # Directory - check for common patterns
        files = list(path.rglob("*"))
        
        tf_files = [f for f in files if f.suffix == ".tf"]
        if tf_files:
            return "terraform"
        
        serverless_files = [f for f in files if f.name.lower() in ("serverless.yml", "serverless.yaml")]
        if serverless_files:
            return "serverless"
        
        cfn_files = [f for f in files if "cloudformation" in str(f).lower() or f.suffix == ".template"]
        if cfn_files:
            return "cloudformation"
        
        return "terraform"  # Default

    async def _run_checkov(self, target_path: Path, framework: str) -> dict:
        """
        Run Checkov on the target path.
        
        Args:
            target_path: Path to scan
            framework: IaC framework
            
        Returns:
            Checkov JSON output
        """
        # Build command
        cmd = [
            "checkov",
            "-o", "json",
            "--quiet",
            "--compact",
        ]
        
        # Add framework
        framework_flag = {
            "terraform": "--framework", 
            "cloudformation": "--framework",
            "serverless": "--framework",
            "kubernetes": "--framework",
        }
        
        checkov_framework = {
            "terraform": "terraform",
            "cloudformation": "cloudformation",
            "serverless": "serverless",
            "kubernetes": "kubernetes",
        }
        
        cmd.extend([framework_flag.get(framework, "--framework"), 
                    checkov_framework.get(framework, "all")])
        
        # Add target
        if target_path.is_file():
            cmd.extend(["--file", str(target_path)])
        else:
            cmd.extend(["--directory", str(target_path)])
        
        # Add skip checks
        if self.skip_checks:
            cmd.extend(["--skip-check", ",".join(self.skip_checks)])
        
        # Add custom rules
        if self.custom_rules_path:
            cmd.extend(["--external-checks-dir", self.custom_rules_path])
        
        self._debug_log(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )
            
            # Checkov returns non-zero on findings
            output = result.stdout
            
            if not output:
                self._debug_log(f"Checkov stderr: {result.stderr}")
                return {"results": {"passed_checks": [], "failed_checks": [], "skipped_checks": []}}
            
            # Parse JSON output
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                # Sometimes Checkov returns multiple JSON objects
                lines = output.strip().split('\n')
                for line in lines:
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue
                
                raise IaCScanError("Failed to parse Checkov output")
                
        except subprocess.TimeoutExpired:
            raise IaCScanError("Checkov scan timed out")
        except FileNotFoundError:
            raise IaCScanError("Checkov is not installed. Install with: pip install checkov")

    def _parse_checkov_results(self, results: dict) -> None:
        """Parse Checkov results and create findings."""
        # Handle both single and multi-framework results
        if isinstance(results, list):
            for framework_result in results:
                self._parse_framework_results(framework_result)
        else:
            self._parse_framework_results(results)

    def _parse_framework_results(self, results: dict) -> None:
        """Parse results for a single framework."""
        check_results = results.get("results", results)
        
        # Count stats
        passed = check_results.get("passed_checks", [])
        failed = check_results.get("failed_checks", [])
        skipped = check_results.get("skipped_checks", [])
        
        self._stats["checks_passed"] += len(passed)
        self._stats["checks_failed"] += len(failed)
        self._stats["checks_skipped"] += len(skipped)
        
        # Process failed checks
        for check in failed:
            self._stats["files_scanned"] += 1
            
            # Map severity
            severity_str = check.get("severity", check.get("check_result", {}).get("severity", "MEDIUM"))
            severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)
            
            # Create finding
            finding = Finding(
                rule_id=check.get("check_id", "UNKNOWN"),
                severity=severity,
                title=check.get("check_name", "Unknown Check"),
                description=self._build_description(check),
                file_path=check.get("file_path", ""),
                line_number=check.get("file_line_range", [0])[0] if check.get("file_line_range") else None,
                resource_id=check.get("resource", ""),
                resource_type=check.get("resource_type", ""),
                suggestion=check.get("guideline", "Review and fix the configuration"),
                metadata={
                    "check_type": check.get("check_type", ""),
                    "bc_check_id": check.get("bc_check_id", ""),
                    "evaluations": check.get("evaluations"),
                    "code_block": check.get("code_block"),
                },
            )
            
            self.add_finding(finding)
            self._scan_logger.finding(severity.value, check.get("check_name", ""), check.get("file_path", ""))

    def _build_description(self, check: dict) -> str:
        """Build a description from check result."""
        parts = []
        
        if check.get("check_name"):
            parts.append(check["check_name"])
        
        if check.get("resource"):
            parts.append(f"Resource: {check['resource']}")
        
        if check.get("file_path"):
            line_range = check.get("file_line_range", [])
            if line_range:
                parts.append(f"Location: {check['file_path']}:{line_range[0]}-{line_range[-1]}")
            else:
                parts.append(f"Location: {check['file_path']}")
        
        return " | ".join(parts)
