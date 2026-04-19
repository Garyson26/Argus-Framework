"""
Compliance Framework Mapper for Argus.

Maps security findings to compliance frameworks and standards including:
- CIS Benchmarks
- SOC 2 Type II
- HIPAA
- PCI DSS
- NIST 800-53
- ISO 27001

Enables compliance-focused reporting and gap analysis.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from src.core.logger import get_logger
from src.scanners.base import Finding, Severity

logger = get_logger(__name__)


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    
    CIS_AWS = "CIS AWS Foundations Benchmark"
    CIS_K8S = "CIS Kubernetes Benchmark"
    SOC2 = "SOC 2 Type II"
    HIPAA = "HIPAA Security Rule"
    PCI_DSS = "PCI DSS v4.0"
    NIST_800_53 = "NIST 800-53"
    ISO_27001 = "ISO 27001:2022"
    GDPR = "GDPR"


@dataclass
class ComplianceControl:
    """
    Represents a compliance control/requirement.
    
    Attributes:
        framework: Compliance framework
        control_id: Control identifier (e.g., CIS 1.1)
        title: Control title
        description: Control description
        severity: Control importance level
        category: Control category
    """
    
    framework: ComplianceFramework
    control_id: str
    title: str
    description: str
    severity: Severity
    category: str


@dataclass
class ComplianceMapping:
    """
    Maps rule IDs to compliance controls.
    
    Attributes:
        rule_id: Argus rule identifier
        controls: List of mapped compliance controls
    """
    
