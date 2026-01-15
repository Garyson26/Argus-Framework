"""
Report generator for FuFuFaFa.

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
        report_name = report_name or f"fufufafa_report_{timestamp}"
        
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
                "generator": "FuFuFaFa Security Audit Framework",
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
            "# 🛡️ FuFuFaFa Security Audit Report",
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
            "*Report generated by [FuFuFaFa](https://github.com/Masriyan/FuFuFaFa) Security Audit Framework*",
        ])
        
        path.write_text("\n".join(lines))
        return path

    def _generate_html(self, results: dict, name: str) -> Path:
        """Generate HTML report."""
        path = self.output_dir / f"{name}.html"
        
        findings = results.get("findings", [])
        severity_counts = results.get("severity_counts", {})
        total = results.get("total_findings", len(findings))
        
        # Build HTML content
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FuFuFaFa Security Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #22c55e;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-yellow: #eab308;
            --accent-blue: #3b82f6;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid var(--bg-card);
            margin-bottom: 2rem;
        }}
        
        .logo {{
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(135deg, var(--accent-green), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        
        .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .summary-card {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            border-left: 4px solid var(--accent-blue);
        }}
        
        .summary-card.critical {{ border-color: var(--accent-red); }}
        .summary-card.high {{ border-color: var(--accent-orange); }}
        .summary-card.medium {{ border-color: var(--accent-yellow); }}
        .summary-card.low {{ border-color: var(--accent-blue); }}
        .summary-card.info {{ border-color: var(--text-secondary); }}
        
        .summary-value {{
            font-size: 2rem;
            font-weight: bold;
        }}
        
        .summary-label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        
        .findings-section {{
            margin-top: 2rem;
        }}
        
        .section-title {{
            font-size: 1.5rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .finding {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--accent-blue);
        }}
        
        .finding.critical {{ border-color: var(--accent-red); }}
        .finding.high {{ border-color: var(--accent-orange); }}
        .finding.medium {{ border-color: var(--accent-yellow); }}
        .finding.low {{ border-color: var(--accent-blue); }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }}
        
        .finding-title {{
            font-size: 1.1rem;
            font-weight: 600;
        }}
        
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: var(--accent-red); }}
        .severity-badge.high {{ background: var(--accent-orange); }}
        .severity-badge.medium {{ background: var(--accent-yellow); color: #000; }}
        .severity-badge.low {{ background: var(--accent-blue); }}
        
        .finding-body {{
            color: var(--text-secondary);
        }}
        
        .finding-meta {{
            margin-top: 1rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
            font-size: 0.85rem;
        }}
        
        .finding-meta code {{
            background: var(--bg-card);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
        }}
        
        .suggestion {{
            margin-top: 1rem;
            padding: 1rem;
            background: rgba(34, 197, 94, 0.1);
            border-radius: 8px;
            border-left: 3px solid var(--accent-green);
        }}
        
        .suggestion-title {{
            color: var(--accent-green);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}
        
        footer {{
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid var(--bg-card);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️ FuFuFaFa</div>
            <h1>Security Audit Report</h1>
            <div class="meta">
                <p>Target: {results.get('target', 'Unknown')}</p>
                <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </header>
        
        <section class="summary-grid">
            <div class="summary-card critical">
                <div class="summary-value">{severity_counts.get('critical', 0)}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-value">{severity_counts.get('high', 0)}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-value">{severity_counts.get('medium', 0)}</div>
                <div class="summary-label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="summary-value">{severity_counts.get('low', 0)}</div>
                <div class="summary-label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="summary-value">{severity_counts.get('info', 0)}</div>
                <div class="summary-label">Info</div>
            </div>
        </section>
        
        <section class="findings-section">
            <h2 class="section-title">🔍 Findings ({total})</h2>
'''
        
        # Add findings
        for finding in sorted(findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.get("severity", "info").lower())):
            severity = finding.get("severity", "info").lower()
            html += f'''
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{finding.get('title', 'Unknown')}</div>
                    <span class="severity-badge {severity}">{severity}</span>
                </div>
                <div class="finding-body">
                    <p>{finding.get('description', 'No description')}</p>
                    <div class="finding-meta">
                        <div><strong>Rule:</strong> <code>{finding.get('rule_id', 'N/A')}</code></div>
'''
            
            if finding.get("resource_id"):
                html += f'                        <div><strong>Resource:</strong> <code>{finding["resource_id"]}</code></div>\n'
            
            if finding.get("file_path"):
                location = finding["file_path"]
                if finding.get("line_number"):
                    location += f":{finding['line_number']}"
                html += f'                        <div><strong>Location:</strong> <code>{location}</code></div>\n'
            
            html += '                    </div>\n'
            
            if finding.get("suggestion"):
                html += f'''
                    <div class="suggestion">
                        <div class="suggestion-title">💡 Remediation</div>
                        <p>{finding['suggestion']}</p>
                    </div>
'''
            
            html += '                </div>\n            </div>\n'
        
        html += '''
        </section>
        
        <footer>
            <p>Generated by FuFuFaFa Security Audit Framework v0.1.0</p>
            <p>Framework for Unified Flaw & Fault Auditing</p>
        </footer>
    </div>
</body>
</html>
'''
        
        path.write_text(html)
        return path
