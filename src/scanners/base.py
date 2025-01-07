"""
Base scanner class for all Argus scanners.

Provides common interface and utilities for scanner implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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
    
