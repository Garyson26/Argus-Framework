"""
Custom YAML Rules Engine for FuFuFaFa.

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
    Custom rules engine for FuFuFaFa.
    
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
    
    def _parse_rule(self, data: dict) -> Optional[CustomRule]:
        """
        Parse rule data into a CustomRule object.
        
        Args:
            data: Rule data dictionary
            
        Returns:
            CustomRule object or None if invalid
        """
        try:
            # Required fields
            rule_id = data.get("id")
            name = data.get("name")
            pattern = data.get("pattern")
            severity_str = data.get("severity", "medium").lower()
            
            if not all([rule_id, name, pattern]):
                logger.warning(f"Rule missing required fields: {data}")
                return None
            
            # Parse severity
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)
            
            return CustomRule(
                id=rule_id,
                name=name,
                pattern=pattern,
                severity=severity,
                description=data.get("description", ""),
                suggestion=data.get("suggestion", "Review this finding"),
                file_patterns=data.get("file_patterns", ["*"]),
                exclude_patterns=data.get("exclude_patterns", []),
                confidence=data.get("confidence", 0.9),
                keywords=data.get("keywords", []),
                enabled=data.get("enabled", True),
                metadata=data.get("metadata", {}),
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse rule: {e}")
            return None
    
    def add_rule(self, rule: CustomRule) -> None:
        """Add a rule to the engine."""
        self._rules.append(rule)
    
    def get_rules_for_file(self, file_path: str) -> list[CustomRule]:
        """
        Get rules applicable to a specific file.
        
        Args:
            file_path: File path to check
            
        Returns:
            List of applicable rules
        """
        return [
            rule for rule in self.rules
            if rule.enabled and rule.matches_file(file_path)
        ]
    
    def get_rules_by_severity(self, severity: Severity) -> list[CustomRule]:
        """Get rules with a specific severity."""
        return [
            rule for rule in self.rules
            if rule.enabled and rule.severity == severity
        ]
    
    def get_rule_by_id(self, rule_id: str) -> Optional[CustomRule]:
        """Get a rule by its ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID."""
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID."""
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False


# Default rules engine instance
_default_engine: Optional[RulesEngine] = None


def get_rules_engine() -> RulesEngine:
    """Get the default rules engine instance."""
    global _default_engine
    if _default_engine is None:
        # Default to project rules directory
        from pathlib import Path
        project_root = Path(__file__).parent.parent.parent
        rules_dir = project_root / "rules"
        _default_engine = RulesEngine(rules_dir=str(rules_dir))
    return _default_engine


def load_rules_from_file(path: str) -> list[CustomRule]:
    """
    Load rules from a single YAML file.
    
    Args:
        path: Path to YAML file
        
    Returns:
        List of loaded rules
    """
    engine = RulesEngine(rules_files=[path])
    engine.load_rules()
    return engine.rules
