"""Unit tests for base scanner classes."""

import pytest
from datetime import datetime

from src.scanners.base import BaseScanner, Finding, ScanResult, Severity


class TestFinding:
    """Tests for Finding dataclass."""
    
    def test_finding_creation(self):
        """Should create finding with required fields."""
        finding = Finding(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            title="Test Finding",
            description="This is a test finding",
        )
        
        assert finding.rule_id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.title == "Test Finding"
    
    def test_finding_to_dict(self):
        """Should convert finding to dictionary."""
        finding = Finding(
            rule_id="TEST-001",
            severity=Severity.CRITICAL,
            title="Critical Issue",
            description="Critical security issue",
            resource_id="bucket-123",
            suggestion="Fix it immediately",
        )
        
        result = finding.to_dict()
        
        assert result["rule_id"] == "TEST-001"
        assert result["severity"] == "critical"
        assert result["resource_id"] == "bucket-123"
        assert result["suggestion"] == "Fix it immediately"
    
    def test_finding_with_location(self):
        """Should include location information."""
        finding = Finding(
            rule_id="SECRET-001",
            severity=Severity.HIGH,
            title="Secret Found",
            description="API key found",
            file_path="src/config.py",
            line_number=42,
            commit_hash="abc123def",
        )
        
        result = finding.to_dict()
        
        assert result["file_path"] == "src/config.py"
        assert result["line_number"] == 42
        assert result["commit_hash"] == "abc123def"


