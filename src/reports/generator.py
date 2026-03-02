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

    def _generate_json(self, results: dict, name: str) -> Path:
        """Generate JSON report."""
        path = self.output_dir / f"{name}.json"
        
        report = {
            "report_info": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "Argus Security Audit Framework",
                "version": "0.1.0",
            },
            "scan_results": results,
        }
        
        path.write_text(json.dumps(report, indent=2, default=str))
        return path

    def _generate_markdown(self, results: dict, name: str) -> Path:
        """Generate Markdown report."""
        path = self.output_dir / f"{name}.md"
        
        findings = results.get("findings", [])
        
        # Build markdown content
        lines = [
            "# 🛡️ Argus Security Audit Report",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Target:** {results.get('target', 'Unknown')}",
            f"**Scan Type:** {results.get('scan_type', 'Unknown')}",
            f"**Status:** {results.get('status', 'Unknown')}",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
        ]
        
        # Summary table
        severity_counts = results.get("severity_counts", {})
        total = results.get("total_findings", len(findings))
        
        lines.extend([
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🚨 Critical | {severity_counts.get('critical', 0)} |",
            f"| ⚠️ High | {severity_counts.get('high', 0)} |",
            f"| ⚡ Medium | {severity_counts.get('medium', 0)} |",
            f"| 📝 Low | {severity_counts.get('low', 0)} |",
            f"| ℹ️ Info | {severity_counts.get('info', 0)} |",
            f"| **Total** | **{total}** |",
            "",
        ])
        
        # Risk assessment
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        
        if critical > 0:
            risk_level = "🔴 **CRITICAL**"
            risk_desc = "Immediate action required. Critical vulnerabilities found."
        elif high > 0:
            risk_level = "🟠 **HIGH**"
            risk_desc = "Significant security issues require prompt attention."
        elif total > 0:
            risk_level = "🟡 **MODERATE**"
            risk_desc = "Security improvements recommended."
        else:
            risk_level = "🟢 **LOW**"
            risk_desc = "No significant security issues found."
        
        lines.extend([
            f"**Overall Risk Level:** {risk_level}",
            f"> {risk_desc}",
            "",
            "---",
            "",
            "## 🔍 Detailed Findings",
            "",
        ])
        
        # Group findings by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        findings_by_severity = {}
        
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            if sev not in findings_by_severity:
                findings_by_severity[sev] = []
            findings_by_severity[sev].append(finding)
        
        severity_icons = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "⚡",
            "low": "📝",
            "info": "ℹ️",
        }
        
        for severity in severity_order:
            sev_findings = findings_by_severity.get(severity, [])
            if not sev_findings:
                continue
            
            icon = severity_icons.get(severity, "📌")
            lines.extend([
                f"### {icon} {severity.upper()} ({len(sev_findings)})",
                "",
            ])
            
            for i, finding in enumerate(sev_findings, 1):
                lines.extend([
                    f"#### {i}. {finding.get('title', 'Unknown')}",
                    "",
                    f"**Rule ID:** `{finding.get('rule_id', 'N/A')}`",
                    "",
                    f"**Description:** {finding.get('description', 'No description')}",
                    "",
                ])
                
                if finding.get("resource_id"):
                    lines.append(f"**Resource:** `{finding['resource_id']}`")
                    lines.append("")
                
                if finding.get("file_path"):
                    location = finding["file_path"]
                    if finding.get("line_number"):
                        location += f":{finding['line_number']}"
                    lines.append(f"**Location:** `{location}`")
                    lines.append("")
                
                if finding.get("suggestion"):
                    lines.extend([
                        "**Remediation:**",
                        f"> {finding['suggestion']}",
                        "",
                    ])
                
                lines.append("---")
                lines.append("")
        
        # Recommendations section
        lines.extend([
            "## 💡 Recommendations",
            "",
            "1. **Address Critical Issues First** - Focus on critical and high severity findings",
            "2. **Rotate Compromised Credentials** - Immediately rotate any exposed secrets",
            "3. **Apply Least Privilege** - Review and restrict overly permissive policies",
            "4. **Enable Encryption** - Ensure data at rest and in transit is encrypted",
            "5. **Monitor and Audit** - Enable CloudTrail, VPC Flow Logs, and access logging",
            "",
            "---",
            "",
            "*Report generated by [Argus](https://github.com/Garyson26/Argus-Framework) Security Audit Framework*",
        ])
        
        path.write_text("\n".join(lines))
        return path

