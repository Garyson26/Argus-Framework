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
    
