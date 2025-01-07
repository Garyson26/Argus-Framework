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
    
