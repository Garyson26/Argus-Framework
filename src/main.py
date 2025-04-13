"""
Main CLI entry point for Argus.

Provides a beautiful, user-friendly command-line interface using Typer.
"""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src import __version__
from src.config import get_settings
from src.core.logger import setup_logging, console as log_console

# Initialize Typer app
app = typer.Typer(
    name="argus",
    help="🛡️ Argus - Automated Risk & Governance Unified Scanner",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# Sub-command groups
secret_app = typer.Typer(help="🔐 Secret leak detection commands")
cloud_app = typer.Typer(help="☁️ AWS cloud misconfiguration scanning commands")
iac_app = typer.Typer(help="📜 Infrastructure as Code scanning commands")
iam_app = typer.Typer(help="👤 IAM permission analysis commands")

app.add_typer(secret_app, name="secret")
app.add_typer(cloud_app, name="cloud")
app.add_typer(iac_app, name="iac")
app.add_typer(iam_app, name="iam")

console = Console()

# ASCII art banner
BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗                 ║
║                ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝                 ║
║                ███████║██████╔╝██║  ███╗██║   ██║███████╗                 ║
║                ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║                 ║
║                ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║                 ║
║                ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝                 ║
║                                                                           ║
║                Automated Risk & Governance Unified Scanner                ║
║                  AWS Cloud Security, Always Watching 👁️                  ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(Panel(
            f"[bold cyan]Argus[/] v{__version__}\n"
            "[dim]Automated Risk & Governance Unified Scanner[/]",
            title="🛡️ Version Info",
            border_style="cyan"
        ))
        raise typer.Exit()


def banner_callback(value: bool) -> None:
    """Print banner and exit."""
    if value:
        console.print(f"[bold cyan]{BANNER}[/]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
    banner: Optional[bool] = typer.Option(
        None,
        "--banner",
        callback=banner_callback,
        is_eager=True,
        help="Show ASCII banner and exit",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-d",
        help="Enable debug mode with verbose logging",
    ),
) -> None:
    """
    🛡️ Argus - Automated Risk & Governance Unified Scanner
    
    A comprehensive AWS cloud security audit tool that helps you identify:
    
    • 🔐 Secret leaks in repositories
    • ☁️ AWS cloud misconfigurations  
    • 📜 Infrastructure as Code vulnerabilities
    • 👤 IAM permission abuse and escalation paths
    
    Use [bold]argus --help[/] to see available commands.
    """
    log_level = "DEBUG" if debug else None
    setup_logging(log_level)


# =============================================================================
# SECRET COMMANDS
# =============================================================================

@secret_app.command("scan")
def secret_scan(
    path: Path = typer.Argument(
        ...,
        help="Path to repository or directory to scan",
        exists=True,
    ),
    scan_history: bool = typer.Option(
        True,
        "--history/--no-history",
        "-h/-H",
        help="Scan git commit history (not just current files)",
    ),
    max_commits: int = typer.Option(
        1000,
        "--max-commits",
        "-m",
        help="Maximum number of commits to scan in history",
    ),
    entropy_threshold: float = typer.Option(
        4.5,
        "--entropy",
        "-e",
        help="Entropy threshold for high-entropy string detection (3.0-6.0)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for results (JSON format)",
    ),
) -> None:
    """
    🔐 Scan a repository or directory for secret leaks.
    
    Detects hardcoded credentials, API keys, private keys, and other sensitive data
    using pattern matching and entropy analysis.
    
    Examples:
        argus secret scan ./my-repo
        argus secret scan ./my-repo --no-history
        argus secret scan ./my-repo -o results.json
    """
    console.print(Panel(
        f"[bold]Scanning for secrets in:[/] {path}\n"
        f"[dim]History: {scan_history} | Max commits: {max_commits} | Entropy: {entropy_threshold}[/]",
        title="🔐 Secret Scan",
        border_style="yellow"
    ))
    
    # Import scanner module (lazy import for faster CLI startup)
    from src.scanners.secrets.scanner import SecretScanner
    
    scanner = SecretScanner(
        scan_git_history=scan_history,
        max_commits=max_commits,
        entropy_threshold=entropy_threshold,
    )
    
    # Run scan
    results = asyncio.run(scanner.scan(str(path)))
    
    # Display results summary
    _display_scan_results(results, "Secret Scan", output)


# =============================================================================
# CLOUD COMMANDS
# =============================================================================

@cloud_app.command("scan")
def cloud_scan(
    profile: Optional[str] = typer.Argument(
        None,
        help="AWS profile name (uses default if not specified)",
    ),
    regions: Optional[str] = typer.Option(
        None,
        "--regions",
        "-r",
        help="Comma-separated list of AWS regions to scan (default: all regions)",
    ),
    services: Optional[str] = typer.Option(
        None,
        "--services",
        "-s",
        help="Comma-separated list of services to scan (s3,ec2,iam,rds,lambda,vpc)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for results (JSON format)",
    ),
) -> None:
    """
    ☁️ Scan AWS account for security misconfigurations.
    
    Checks S3 buckets, EC2 instances, IAM policies, RDS databases, and more
    for common security issues.
    
    Examples:
        argus cloud scan
        argus cloud scan my-profile
        argus cloud scan --regions us-east-1,eu-west-1
        argus cloud scan -s s3,iam -o results.json
    """
    profile_display = profile or "default"
    regions_display = regions or "all"
    
    console.print(Panel(
        f"[bold]AWS Profile:[/] {profile_display}\n"
        f"[bold]Regions:[/] {regions_display}\n"
        f"[bold]Services:[/] {services or 'all'}",
        title="☁️ AWS Cloud Scan",
        border_style="blue"
    ))
    
    # Parse options
    region_list = regions.split(",") if regions else None
    service_list = services.split(",") if services else None
    
    # Import scanner module
    from src.scanners.aws_cloud.scanner import AWSCloudScanner
    
    scanner = AWSCloudScanner(
        profile=profile,
        regions=region_list,
        services=service_list,
    )
    
    # Run scan
    results = asyncio.run(scanner.scan())
    
    # Display results summary
    _display_scan_results(results, "AWS Cloud Scan", output)


# =============================================================================
# IAC COMMANDS
# =============================================================================

@iac_app.command("scan")
def iac_scan(
    path: Path = typer.Argument(
        ...,
        help="Path to IaC files or directory",
        exists=True,
    ),
    framework: Optional[str] = typer.Option(
        None,
        "--framework",
        "-f",
        help="IaC framework (terraform, cloudformation, serverless, kubernetes). Auto-detected if not specified.",
    ),
    skip_checks: Optional[str] = typer.Option(
        None,
        "--skip",
        help="Comma-separated list of check IDs to skip",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for results (JSON format)",
    ),
) -> None:
    """
    📜 Scan Infrastructure as Code files for security issues.
    
    Supports Terraform, CloudFormation, Serverless Framework, and Kubernetes manifests.
    Uses Checkov as the underlying scanning engine.
    
    Examples:
        argus iac scan ./terraform/
        argus iac scan ./cloudformation/template.yaml
        argus iac scan ./k8s/ -f kubernetes
    """
    console.print(Panel(
        f"[bold]Scanning IaC at:[/] {path}\n"
        f"[bold]Framework:[/] {framework or 'auto-detect'}\n"
        f"[bold]Skip checks:[/] {skip_checks or 'none'}",
        title="📜 IaC Scan",
        border_style="green"
    ))
    
    # Parse options
    skip_list = skip_checks.split(",") if skip_checks else None
    
    # Import scanner module
    from src.scanners.iac.scanner import IaCScanner
    
