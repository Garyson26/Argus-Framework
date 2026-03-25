"""
Container Security Scanner for Argus.

Scans container images and Kubernetes manifests for security issues.

Features:
- Docker image vulnerability scanning (via Trivy integration)
- Kubernetes manifest security checks
- Dockerfile best practices validation
- Container runtime security analysis
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.config import get_settings
from src.core.exceptions import ScanError
from src.core.logger import ScanLogger, get_logger
from src.scanners.base import BaseScanner, Finding, Severity
from src.utils.progress import ScanProgress

logger = get_logger(__name__)


# Kubernetes security checks
K8S_SECURITY_CHECKS = {
    "privileged_container": {
        "pattern": r"privileged\s*:\s*true",
        "severity": Severity.CRITICAL,
        "title": "Privileged Container",
        "description": "Container runs with privileged mode enabled",
        "suggestion": "Avoid running containers in privileged mode unless absolutely necessary",
    },
    "host_network": {
        "pattern": r"hostNetwork\s*:\s*true",
        "severity": Severity.HIGH,
        "title": "Host Network Mode",
        "description": "Container uses host network namespace",
        "suggestion": "Use pod-specific network namespaces for isolation",
    },
    "host_pid": {
        "pattern": r"hostPID\s*:\s*true",
        "severity": Severity.HIGH,
        "title": "Host PID Namespace",
        "description": "Container shares host PID namespace",
        "suggestion": "Avoid sharing host PID namespace",
    },
    "host_ipc": {
        "pattern": r"hostIPC\s*:\s*true",
        "severity": Severity.HIGH,
        "title": "Host IPC Namespace",
        "description": "Container shares host IPC namespace",
        "suggestion": "Avoid sharing host IPC namespace",
    },
    "run_as_root": {
        "pattern": r"runAsUser\s*:\s*0",
        "severity": Severity.HIGH,
        "title": "Container Runs as Root",
        "description": "Container explicitly runs as root user",
        "suggestion": "Run containers as non-root user",
    },
    "allow_privilege_escalation": {
        "pattern": r"allowPrivilegeEscalation\s*:\s*true",
        "severity": Severity.HIGH,
        "title": "Privilege Escalation Allowed",
        "description": "Container allows privilege escalation",
        "suggestion": "Set allowPrivilegeEscalation to false",
    },
    "no_resource_limits": {
        "pattern": r"resources\s*:\s*\{\s*\}",
        "severity": Severity.MEDIUM,
        "title": "No Resource Limits",
        "description": "Container has no resource limits defined",
        "suggestion": "Define CPU and memory limits for containers",
    },
    "latest_tag": {
        "pattern": r"image\s*:\s*['\"]?[^:'\"\s]+:latest",
        "severity": Severity.MEDIUM,
        "title": "Using Latest Tag",
        "description": "Container image uses 'latest' tag",
        "suggestion": "Use specific image tags for reproducibility",
    },
    "no_security_context": {
        "pattern": r"spec:\s*\n(?!.*securityContext)",
        "severity": Severity.MEDIUM,
        "title": "Missing Security Context",
        "description": "Container spec missing security context",
        "suggestion": "Define securityContext for pods and containers",
    },
    "secrets_in_env": {
        "pattern": r"valueFrom\s*:\s*\n\s*secretKeyRef",
        "severity": Severity.LOW,
        "title": "Secrets via Environment",
        "description": "Secrets exposed as environment variables",
        "suggestion": "Consider using volume mounts for secrets instead",
    },
}

# Dockerfile security checks
DOCKERFILE_CHECKS = {
    "root_user": {
        "pattern": r"^USER\s+root\s*$",
        "severity": Severity.HIGH,
        "title": "Running as Root User",
        "description": "Dockerfile explicitly sets USER to root",
        "suggestion": "Create and use a non-root user",
    },
    "no_user_directive": {
        "anti_pattern": r"^USER\s+",
        "severity": Severity.MEDIUM,
        "title": "No USER Directive",
        "description": "Dockerfile does not specify a USER",
        "suggestion": "Add USER directive to run as non-root",
    },
    "add_instead_of_copy": {
        "pattern": r"^ADD\s+(?!https?://)",
        "severity": Severity.LOW,
        "title": "ADD Used Instead of COPY",
        "description": "ADD instruction used for local files",
        "suggestion": "Use COPY for local files, ADD only for URLs or tar extraction",
    },
    "latest_base_image": {
        "pattern": r"^FROM\s+\S+:latest",
        "severity": Severity.MEDIUM,
        "title": "Latest Base Image Tag",
        "description": "Base image uses 'latest' tag",
        "suggestion": "Pin base image to specific version",
    },
    "curl_wget_install": {
        "pattern": r"(curl|wget)\s+.*(http|https).*\|\s*(bash|sh)",
        "severity": Severity.HIGH,
        "title": "Piped Script Installation",
        "description": "Script downloaded and piped to shell",
        "suggestion": "Download and verify scripts before execution",
    },
    "apt_no_cleanup": {
        "pattern": r"apt(-get)?\s+install(?!.*rm\s+-rf\s+/var/lib/apt)",
        "severity": Severity.LOW,
        "title": "APT Cache Not Cleaned",
        "description": "apt-get install without cache cleanup",
        "suggestion": "Add 'rm -rf /var/lib/apt/lists/*' after apt operations",
    },
    "expose_22": {
        "pattern": r"^EXPOSE\s+22\b",
        "severity": Severity.MEDIUM,
        "title": "SSH Port Exposed",
        "description": "Container exposes SSH port 22",
        "suggestion": "Avoid SSH in containers; use kubectl exec or docker exec",
    },
    "env_secrets": {
        "pattern": r"^ENV\s+\S*(password|secret|key|token)\S*\s*=",
        "severity": Severity.CRITICAL,
        "title": "Secrets in ENV",
        "description": "Potential secrets hardcoded in ENV",
        "suggestion": "Use build args or runtime secrets injection",
    },
}


@dataclass
class ContainerScanTarget:
    """Container scan target information."""
    
    target_type: str  # "image", "dockerfile", "k8s_manifest", "directory"
    path: str
    name: Optional[str] = None


class ContainerScanner(BaseScanner):
    """
    Container security scanner.
    
    Scans container images and configurations for:
    - Vulnerabilities in container images (via Trivy)
    - Security misconfigurations in Kubernetes manifests
    - Dockerfile best practices violations
    """
    
    scanner_type = "container"
    
    # K8s manifest file patterns
    K8S_PATTERNS = ("*.yaml", "*.yml", "*.json")
    K8S_KEYWORDS = ("apiVersion", "kind", "metadata", "spec")
    
    def __init__(
        self,
        use_trivy: bool = True,
        trivy_severity: str = "CRITICAL,HIGH,MEDIUM",
        scan_k8s: bool = True,
        scan_dockerfiles: bool = True,
        debug: bool = False,
        show_progress: bool = True,
    ):
        """
        Initialize the container scanner.
        
        Args:
            use_trivy: Use Trivy for image scanning if available
            trivy_severity: Minimum severity for Trivy findings
            scan_k8s: Scan Kubernetes manifests
            scan_dockerfiles: Scan Dockerfiles
            debug: Enable debug mode
            show_progress: Show progress bar
        """
        super().__init__()
        
        self.use_trivy = use_trivy
        self.trivy_severity = trivy_severity
        self.scan_k8s = scan_k8s
        self.scan_dockerfiles = scan_dockerfiles
        self.debug = debug
        self.show_progress = show_progress
        
        self._trivy_available = self._check_trivy()
        self._scan_logger: Optional[ScanLogger] = None
        self._progress: Optional[ScanProgress] = None
        self._stats = {
            "images_scanned": 0,
            "manifests_scanned": 0,
            "dockerfiles_scanned": 0,
            "vulnerabilities_found": 0,
        }
    
    def _check_trivy(self) -> bool:
        """Check if Trivy is installed."""
        return shutil.which("trivy") is not None
    
    async def scan(self, target: str) -> dict[str, Any]:
        """
        Scan container target for security issues.
        
        Args:
            target: Image name, directory path, or file path
            
        Returns:
            Scan results dictionary
        """
        started_at = datetime.utcnow()
        self.clear_findings()
        
        self._scan_logger = ScanLogger("container", target)
        self._scan_logger.start()
        
        try:
            # Determine target type
            scan_target = self._identify_target(target)
            self._debug_log(f"Target type: {scan_target.target_type}")
            
            if self.show_progress:
                self._progress = ScanProgress(description="Container Scan")
                self._progress.__enter__()
            
            try:
                if scan_target.target_type == "image":
                    await self._scan_image(scan_target)
                elif scan_target.target_type == "dockerfile":
                    await self._scan_dockerfile(scan_target)
                elif scan_target.target_type == "k8s_manifest":
                    await self._scan_k8s_manifest(scan_target)
                elif scan_target.target_type == "directory":
                    await self._scan_directory(scan_target)
                else:
                    raise ScanError(f"Unknown target type: {scan_target.target_type}")
                    
            finally:
                if self._progress:
                    self._progress.__exit__(None, None, None)
                    if self.show_progress:
                        self._progress.print_summary()
                    self._progress = None
            
            result = self.create_result(
                target=target,
                started_at=started_at,
                metadata={
                    "target_type": scan_target.target_type,
                    "trivy_available": self._trivy_available,
                    **self._stats,
                },
            )
            
            self._scan_logger.end(len(self._findings))
            return result.to_dict()
            
        except Exception as e:
            self._scan_logger.error(f"Container scan failed: {e}", e)
            raise ScanError(f"Container scan failed: {e}")
    
    def _identify_target(self, target: str) -> ContainerScanTarget:
        """Identify the type of scan target."""
        path = Path(target)
        
        # Check if it's a file
        if path.is_file():
            if path.name.lower() in ("dockerfile", "containerfile") or \
               path.name.lower().startswith("dockerfile"):
                return ContainerScanTarget("dockerfile", str(path), path.name)
            
            # Check for K8s manifest
            if path.suffix.lower() in (".yaml", ".yml", ".json"):
                content = path.read_text()
                if any(kw in content for kw in self.K8S_KEYWORDS):
                    return ContainerScanTarget("k8s_manifest", str(path), path.name)
            
            return ContainerScanTarget("file", str(path), path.name)
        
        # Check if it's a directory
        if path.is_dir():
            return ContainerScanTarget("directory", str(path), path.name)
        
        # Assume it's a container image reference
        return ContainerScanTarget("image", target, target)
    
    def _debug_log(self, message: str) -> None:
        """Log debug message."""
        if self.debug:
            logger.debug(f"[CONTAINER] {message}")
    
    async def _scan_image(self, target: ContainerScanTarget) -> None:
        """Scan container image using Trivy."""
        if not self.use_trivy or not self._trivy_available:
            self._debug_log("Trivy not available, skipping image scan")
            self.add_finding(Finding(
                rule_id="CONTAINER-NO-TRIVY",
                severity=Severity.INFO,
                title="Image Scanning Unavailable",
                description=f"Trivy not installed; cannot scan image {target.path}",
                resource_id=target.path,
                resource_type="Container::Image",
                suggestion="Install Trivy for container image vulnerability scanning",
            ))
            return
        
        self._debug_log(f"Scanning image with Trivy: {target.path}")
        self._stats["images_scanned"] += 1
        
        try:
            # Run Trivy scan
            result = subprocess.run(
                [
                    "trivy", "image",
                    "--format", "json",
                    "--severity", self.trivy_severity,
                    target.path,
                ],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            
            if result.returncode != 0:
                self._debug_log(f"Trivy error: {result.stderr}")
                return
            
            # Parse results
            trivy_results = json.loads(result.stdout)
            await self._process_trivy_results(trivy_results, target)
            
        except subprocess.TimeoutExpired:
            self._debug_log("Trivy scan timed out")
        except json.JSONDecodeError as e:
            self._debug_log(f"Failed to parse Trivy output: {e}")
        except Exception as e:
            self._debug_log(f"Error running Trivy: {e}")
    
    async def _process_trivy_results(
        self,
        results: dict,
        target: ContainerScanTarget,
    ) -> None:
        """Process Trivy scan results."""
        for result in results.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                self._stats["vulnerabilities_found"] += 1
                
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "UNKNOWN": Severity.INFO,
                }
                
                self.add_finding(Finding(
                    rule_id=f"VULN-{vuln.get('VulnerabilityID', 'UNKNOWN')}",
                    severity=severity_map.get(vuln.get("Severity", "UNKNOWN"), Severity.INFO),
                    title=f"Vulnerability: {vuln.get('VulnerabilityID', 'Unknown')}",
                    description=vuln.get("Description", "No description available")[:500],
                    resource_id=target.path,
                    resource_type="Container::Image",
                    suggestion=f"Upgrade {vuln.get('PkgName', 'package')} from {vuln.get('InstalledVersion', 'unknown')} to {vuln.get('FixedVersion', 'latest')}",
                    metadata={
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                    },
                ))
    
    async def _scan_dockerfile(self, target: ContainerScanTarget) -> None:
        """Scan Dockerfile for security issues."""
        self._debug_log(f"Scanning Dockerfile: {target.path}")
        self._stats["dockerfiles_scanned"] += 1
        
        try:
            content = Path(target.path).read_text()
            lines = content.split("\n")
            
            for check_id, check in DOCKERFILE_CHECKS.items():
                if "pattern" in check:
                    pattern = re.compile(check["pattern"], re.IGNORECASE | re.MULTILINE)
                    for i, line in enumerate(lines, 1):
                        if pattern.search(line):
                            self.add_finding(Finding(
                                rule_id=f"DOCKERFILE-{check_id.upper()}",
                                severity=check["severity"],
                                title=check["title"],
                                description=check["description"],
                                file_path=target.path,
                                line_number=i,
                                suggestion=check["suggestion"],
                            ))
                            
                elif "anti_pattern" in check:
                    # Check for absence of pattern
                    anti_pattern = re.compile(check["anti_pattern"], re.IGNORECASE | re.MULTILINE)
                    if not anti_pattern.search(content):
                        self.add_finding(Finding(
                            rule_id=f"DOCKERFILE-{check_id.upper()}",
                            severity=check["severity"],
                            title=check["title"],
                            description=check["description"],
                            file_path=target.path,
                            suggestion=check["suggestion"],
                        ))
                        
        except Exception as e:
            self._debug_log(f"Error scanning Dockerfile: {e}")
    
    async def _scan_k8s_manifest(self, target: ContainerScanTarget) -> None:
        """Scan Kubernetes manifest for security issues."""
        self._debug_log(f"Scanning K8s manifest: {target.path}")
        self._stats["manifests_scanned"] += 1
        
        try:
            content = Path(target.path).read_text()
            
            for check_id, check in K8S_SECURITY_CHECKS.items():
                pattern = re.compile(check["pattern"], re.IGNORECASE | re.MULTILINE)
                matches = list(pattern.finditer(content))
                
                for match in matches:
                    # Find line number
                    line_num = content[:match.start()].count("\n") + 1
                    
                    self.add_finding(Finding(
                        rule_id=f"K8S-{check_id.upper()}",
                        severity=check["severity"],
                        title=check["title"],
                        description=check["description"],
                        file_path=target.path,
                        line_number=line_num,
                        suggestion=check["suggestion"],
                    ))
                    
        except Exception as e:
            self._debug_log(f"Error scanning K8s manifest: {e}")
    
    async def _scan_directory(self, target: ContainerScanTarget) -> None:
        """Scan directory for Dockerfiles and K8s manifests."""
        directory = Path(target.path)
        
        # Find Dockerfiles
        if self.scan_dockerfiles:
            for dockerfile in directory.rglob("Dockerfile*"):
                if dockerfile.is_file():
                    await self._scan_dockerfile(
                        ContainerScanTarget("dockerfile", str(dockerfile), dockerfile.name)
                    )
        
        # Find K8s manifests
        if self.scan_k8s:
            for pattern in self.K8S_PATTERNS:
                for manifest in directory.rglob(pattern):
                    if manifest.is_file():
                        try:
                            content = manifest.read_text()
                            if any(kw in content for kw in self.K8S_KEYWORDS):
                                await self._scan_k8s_manifest(
                                    ContainerScanTarget("k8s_manifest", str(manifest), manifest.name)
                                )
                        except Exception:
                            continue
