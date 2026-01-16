"""
Compliance Framework Mapper for FuFuFaFa.

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
        rule_id: FuFuFaFa rule identifier
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
    
    # CloudTrail Controls
    "CLOUDTRAIL-NOT-ENABLED": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 3.1",
        title="Ensure CloudTrail is enabled in all regions",
        description="CloudTrail provides API audit logging",
        severity=Severity.CRITICAL,
        category="Logging",
    ),
    "CLOUDTRAIL-NOT-MULTIREGION": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 3.1",
        title="Ensure CloudTrail is enabled in all regions",
        description="Multi-region logging captures all API activity",
        severity=Severity.MEDIUM,
        category="Logging",
    ),
    "CLOUDTRAIL-NO-LOG-VALIDATION": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 3.2",
        title="Ensure CloudTrail log file validation is enabled",
        description="Log validation detects log tampering",
        severity=Severity.MEDIUM,
        category="Logging",
    ),
    
    # RDS Controls
    "RDS-PUBLIC-ACCESS": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 2.3.2",
        title="Ensure RDS instances are not publicly accessible",
        description="Database should not be exposed to internet",
        severity=Severity.CRITICAL,
        category="Database",
    ),
    "RDS-NO-ENCRYPTION": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 2.3.1",
        title="Ensure RDS encryption is enabled",
        description="Encrypt database storage at rest",
        severity=Severity.HIGH,
        category="Database",
    ),
    
    # EBS Controls
    "EC2-EBS-NOT-ENCRYPTED": ComplianceControl(
        framework=ComplianceFramework.CIS_AWS,
        control_id="CIS 2.2.1",
        title="Ensure EBS volume encryption is enabled",
        description="Encrypt EBS volumes for data protection",
        severity=Severity.MEDIUM,
        category="Storage",
    ),
}

# PCI DSS mappings
PCI_DSS_MAPPINGS = {
    "SECRET-AWS_ACCESS_KEY": ComplianceControl(
        framework=ComplianceFramework.PCI_DSS,
        control_id="PCI 3.4",
        title="Render PAN unreadable anywhere it is stored",
        description="Sensitive authentication data must be protected",
        severity=Severity.CRITICAL,
        category="Protect Cardholder Data",
    ),
    "SECRET-PRIVATE_KEY": ComplianceControl(
        framework=ComplianceFramework.PCI_DSS,
        control_id="PCI 3.5",
        title="Protect cryptographic keys used for encryption",
        description="Private keys must be securely stored",
        severity=Severity.CRITICAL,
        category="Protect Cardholder Data",
    ),
    "RDS-PUBLIC-ACCESS": ComplianceControl(
        framework=ComplianceFramework.PCI_DSS,
        control_id="PCI 1.3",
        title="Prohibit direct public access to the CDE",
        description="Databases should not be publicly accessible",
        severity=Severity.CRITICAL,
        category="Build Secure Network",
    ),
    "EC2-SG-OPEN-SENSITIVE-PORT": ComplianceControl(
        framework=ComplianceFramework.PCI_DSS,
        control_id="PCI 1.2",
        title="Restrict connections between untrusted networks",
        description="Limit inbound traffic to necessary services",
        severity=Severity.CRITICAL,
        category="Build Secure Network",
    ),
}


@dataclass
class ComplianceReport:
    """
    Compliance assessment report.
    
    Attributes:
        framework: Target compliance framework
        total_controls: Total controls in framework
        passed_controls: Controls with no findings
        failed_controls: Controls with findings
        score: Compliance score (0-100)
        findings_by_control: Findings grouped by control
    """
    
    framework: ComplianceFramework
    total_controls: int
    passed_controls: int
    failed_controls: int
    score: float
    findings_by_control: dict[str, list[Finding]] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "total_controls": self.total_controls,
            "passed_controls": self.passed_controls,
            "failed_controls": self.failed_controls,
            "score": round(self.score, 2),
            "findings_count": sum(len(f) for f in self.findings_by_control.values()),
            "controls": {
                ctrl: [f.to_dict() for f in findings]
                for ctrl, findings in self.findings_by_control.items()
            },
        }


class ComplianceMapper:
    """
    Maps findings to compliance framework controls.
    
    Provides compliance-focused analysis and reporting.
    """
    
    def __init__(self):
        """Initialize the compliance mapper."""
        self._mappings: dict[ComplianceFramework, dict[str, ComplianceControl]] = {
            ComplianceFramework.CIS_AWS: CIS_AWS_MAPPINGS,
            ComplianceFramework.PCI_DSS: PCI_DSS_MAPPINGS,
        }
    
    def get_controls_for_finding(
        self,
        finding: Finding,
        frameworks: Optional[list[ComplianceFramework]] = None,
    ) -> list[ComplianceControl]:
        """
        Get compliance controls related to a finding.
        
        Args:
            finding: Security finding
            frameworks: Limit to specific frameworks
            
        Returns:
            List of related compliance controls
        """
        controls = []
        frameworks = frameworks or list(self._mappings.keys())
        
        for framework in frameworks:
            mapping = self._mappings.get(framework, {})
            if finding.rule_id in mapping:
                controls.append(mapping[finding.rule_id])
        
        return controls
    
    def generate_report(
        self,
        findings: list[Finding],
        framework: ComplianceFramework,
    ) -> ComplianceReport:
        """
        Generate compliance report for a framework.
        
        Args:
            findings: List of security findings
            framework: Target compliance framework
            
        Returns:
            ComplianceReport object
        """
        mapping = self._mappings.get(framework, {})
        all_control_ids = set(ctrl.control_id for ctrl in mapping.values())
        
        findings_by_control: dict[str, list[Finding]] = {}
        failed_control_ids = set()
        
        for finding in findings:
            if finding.rule_id in mapping:
                control = mapping[finding.rule_id]
                control_id = control.control_id
                
                if control_id not in findings_by_control:
                    findings_by_control[control_id] = []
                findings_by_control[control_id].append(finding)
                failed_control_ids.add(control_id)
        
        total = len(all_control_ids)
        failed = len(failed_control_ids)
        passed = total - failed
        score = (passed / total * 100) if total > 0 else 100.0
        
        return ComplianceReport(
            framework=framework,
            total_controls=total,
            passed_controls=passed,
            failed_controls=failed,
            score=score,
            findings_by_control=findings_by_control,
        )
    
    def get_supported_frameworks(self) -> list[ComplianceFramework]:
        """Get list of supported compliance frameworks."""
        return list(self._mappings.keys())
    
    def add_mapping(
        self,
        framework: ComplianceFramework,
        rule_id: str,
        control: ComplianceControl,
    ) -> None:
        """
        Add a custom compliance mapping.
        
        Args:
            framework: Target framework
            rule_id: FuFuFaFa rule ID
            control: Compliance control
        """
        if framework not in self._mappings:
            self._mappings[framework] = {}
        self._mappings[framework][rule_id] = control


# Default mapper instance
_default_mapper: Optional[ComplianceMapper] = None


def get_compliance_mapper() -> ComplianceMapper:
    """Get the default compliance mapper instance."""
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = ComplianceMapper()
    return _default_mapper
