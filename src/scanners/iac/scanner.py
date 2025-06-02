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
    
