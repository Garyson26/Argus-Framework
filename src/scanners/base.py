"""
Base scanner class for all FuFuFaFa scanners.

Provides common interface and utilities for scanner implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Severity levels for findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding."""
    
    rule_id: str
    severity: Severity
    title: str
    description: str
    
    # Resource information
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_arn: Optional[str] = None
    
    # Location (for code-based findings)
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    commit_hash: Optional[str] = None
    
    # Remediation
    suggestion: Optional[str] = None
    
    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    confidence: Optional[float] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "resource_arn": self.resource_arn,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "commit_hash": self.commit_hash,
            "suggestion": self.suggestion,
            "metadata": self.metadata,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    """Result of a scan operation."""
    
    scan_type: str
    target: str
    status: str = "completed"
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings: list[Finding] = field(default_factory=list)
    error_message: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)
    
    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Count of high findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        """Count of medium findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        """Count of low findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
    
    @property
    def info_count(self) -> int:
        """Count of info findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_findings": self.total_findings,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


class BaseScanner(ABC):
    """
    Abstract base class for all scanners.
    
    All scanner implementations should inherit from this class and implement
    the abstract methods.
    """
    
    scanner_type: str = "base"
    
    def __init__(self):
        """Initialize the scanner."""
        self._findings: list[Finding] = []
    
    @abstractmethod
    async def scan(self, target: str) -> dict[str, Any]:
        """
        Perform the scan.
        
        Args:
            target: Target to scan (path, profile, etc.)
            
        Returns:
            Dictionary containing scan results
        """
        pass
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self._findings.append(finding)
    
    def clear_findings(self) -> None:
        """Clear all findings."""
        self._findings.clear()
    
    def get_findings(self) -> list[Finding]:
        """Get all findings."""
        return self._findings.copy()
    
    def create_result(
        self,
        target: str,
        started_at: datetime,
        error_message: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ScanResult:
        """
        Create a scan result object.
        
        Args:
            target: Scan target
            started_at: Scan start time
            error_message: Error message if scan failed
            metadata: Additional metadata
            
        Returns:
            ScanResult object
        """
        return ScanResult(
            scan_type=self.scanner_type,
            target=target,
            status="failed" if error_message else "completed",
            started_at=started_at,
            completed_at=datetime.utcnow(),
            findings=self._findings.copy(),
            error_message=error_message,
            metadata=metadata or {},
        )
