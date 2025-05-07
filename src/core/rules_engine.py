"""
Custom YAML Rules Engine for Argus.

Allows users to define custom secret detection patterns and security
rules using YAML configuration files.

Features:
- YAML-based rule definitions
- Pattern matching with regex
- Severity levels and confidence scores
- Rule inheritance and overrides
- File pattern filtering
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from src.core.logger import get_logger
from src.scanners.base import Severity

logger = get_logger(__name__)


@dataclass
class CustomRule:
    """
    Represents a custom security rule.
    
    Attributes:
        id: Unique rule identifier
        name: Human-readable rule name
        pattern: Regex pattern to match
        severity: Finding severity level
        description: Detailed description
        suggestion: Remediation suggestion
        file_patterns: File glob patterns to apply rule to
        exclude_patterns: File patterns to exclude
        confidence: Confidence score (0.0-1.0)
        keywords: Keywords to pre-filter content
        enabled: Whether rule is active
        metadata: Additional metadata
    """
    
    id: str
    name: str
    pattern: str
    severity: Severity
    description: str
    suggestion: str
    file_patterns: list[str] = field(default_factory=lambda: ["*"])
    exclude_patterns: list[str] = field(default_factory=list)
    confidence: float = 0.9
    keywords: list[str] = field(default_factory=list)
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    
    _compiled_pattern: Optional[re.Pattern] = field(default=None, repr=False)
    
    def __post_init__(self) -> None:
        """Compile the regex pattern."""
        try:
            self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.warning(f"Invalid regex pattern for rule {self.id}: {e}")
            self._compiled_pattern = None
    
    @property
    def regex(self) -> Optional[re.Pattern]:
        """Get compiled regex pattern."""
        return self._compiled_pattern
    
    def matches_file(self, file_path: str) -> bool:
        """
        Check if rule should apply to a file.
        
        Args:
            file_path: File path to check
            
        Returns:
            True if rule should apply
        """
        from fnmatch import fnmatch
        
        # Check exclude patterns first
        for pattern in self.exclude_patterns:
            if fnmatch(file_path, pattern):
                return False
        
        # Check include patterns
        for pattern in self.file_patterns:
            if fnmatch(file_path, pattern):
                return True
        
        return False
    
    def has_keywords(self, content: str) -> bool:
        """
        Quick keyword check before regex matching.
        
        Args:
            content: Content to check
            
        Returns:
            True if content contains any keyword
        """
        if not self.keywords:
            return True
        
        content_lower = content.lower()
        return any(kw.lower() in content_lower for kw in self.keywords)
    
    def match(self, content: str) -> list[re.Match]:
        """
        Find all matches in content.
        
        Args:
            content: Content to search
            
        Returns:
            List of regex matches
        """
        if self._compiled_pattern is None:
            return []
        
        return list(self._compiled_pattern.finditer(content))


class RulesEngine:
    """
    Custom rules engine for Argus.
    
    Loads and manages custom rules from YAML files.
    """
    
    def __init__(
        self,
        rules_dir: Optional[str] = None,
        rules_files: Optional[list[str]] = None,
    ):
        """
        Initialize the rules engine.
        
        Args:
            rules_dir: Directory containing rule YAML files
            rules_files: Specific rule files to load
        """
        self.rules_dir = Path(rules_dir) if rules_dir else None
        self.rules_files = rules_files or []
        self._rules: list[CustomRule] = []
        self._loaded = False
    
    @property
    def rules(self) -> list[CustomRule]:
        """Get all loaded rules."""
        if not self._loaded:
            self.load_rules()
        return self._rules
    
    def load_rules(self) -> None:
        """Load all rules from configured sources."""
        self._rules.clear()
        
        # Load from directory
        if self.rules_dir and self.rules_dir.exists():
            for yaml_file in self.rules_dir.glob("**/*.yaml"):
                self._load_file(yaml_file)
            for yml_file in self.rules_dir.glob("**/*.yml"):
                self._load_file(yml_file)
        
        # Load specific files
        for file_path in self.rules_files:
            path = Path(file_path)
            if path.exists():
                self._load_file(path)
        
        self._loaded = True
        logger.info(f"Loaded {len(self._rules)} custom rules")
    
    def _load_file(self, path: Path) -> None:
        """
        Load rules from a YAML file.
        
        Args:
            path: Path to YAML file
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return
            
            rules_data = data.get("rules", [])
            
            for rule_data in rules_data:
                rule = self._parse_rule(rule_data)
                if rule:
                    self._rules.append(rule)
                    
        except yaml.YAMLError as e:
            logger.warning(f"Failed to parse YAML file {path}: {e}")
        except Exception as e:
            logger.warning(f"Failed to load rules from {path}: {e}")
    
