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
    
    rule_id: str
    controls: list[ComplianceControl] = field(default_factory=list)


# =============================================================================
# COMPLIANCE MAPPINGS DATABASE
# =============================================================================

# CIS AWS Foundations Benchmark mappings
CIS_AWS_MAPPINGS = {
    # IAM Controls
    "IAM-NO-PASSWORD-POLICY": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 1.5",
        title="Ensure IAM password policy requires at least one uppercase letter",
        description="IAM password policy should require uppercase letters",
        severity=Severity.MEDIUM,
        category="Identity and Access Management",
    ),
    "IAM-WEAK-PASSWORD-POLICY": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 1.5-1.11",
        title="IAM Password Policy Controls",
        description="Multiple password policy requirements not met",
        severity=Severity.MEDIUM,
        category="Identity and Access Management",
    ),
    "IAM-USER-NO-MFA": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 1.10",
        title="Ensure multi-factor authentication (MFA) is enabled for all IAM users",
        description="MFA adds an extra layer of protection",
        severity=Severity.HIGH,
        category="Identity and Access Management",
    ),
    "IAM-ACCESS-KEY-OLD": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 1.14",
        title="Ensure access keys are rotated every 90 days or less",
        description="Regular key rotation limits exposure window",
        severity=Severity.MEDIUM,
        category="Identity and Access Management",
    ),
    
    # S3 Controls
    "S3-NO-PUBLIC-ACCESS-BLOCK": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 2.1.5",
        title="Ensure S3 Bucket has 'Block Public Access' enabled",
        description="Block public access to prevent data exposure",
        severity=Severity.HIGH,
        category="Storage",
    ),
    "S3-PUBLIC-ACCESS-BLOCK": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 2.1.5",
        title="Ensure S3 Bucket has 'Block Public Access' enabled",
        description="Block public access to prevent data exposure",
        severity=Severity.HIGH,
        category="Storage",
    ),
    "S3-NO-ENCRYPTION": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 2.1.1",
        title="Ensure S3 Bucket has server-side encryption enabled",
        description="Enable encryption at rest for data protection",
        severity=Severity.MEDIUM,
        category="Storage",
    ),
    "S3-NO-LOGGING": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 3.6",
        title="Ensure S3 bucket access logging is enabled",
        description="Access logging provides audit trail",
        severity=Severity.LOW,
        category="Logging",
    ),
    
    # EC2/Network Controls
    "EC2-SG-OPEN-SENSITIVE-PORT": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 5.2",
        title="Ensure no security groups allow ingress from 0.0.0.0/0 to SSH",
        description="Restrict SSH access to known IP ranges",
        severity=Severity.CRITICAL,
        category="Networking",
    ),
    "EC2-SG-OPEN-TO-WORLD": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 5.3",
        title="Ensure no security groups allow unrestricted ingress",
        description="Limit network exposure to required sources",
        severity=Severity.MEDIUM,
        category="Networking",
    ),
    "VPC-NO-FLOW-LOGS": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 3.9",
        title="Ensure VPC flow logging is enabled",
        description="Flow logs enable network traffic analysis",
        severity=Severity.MEDIUM,
        category="Logging",
    ),
    
