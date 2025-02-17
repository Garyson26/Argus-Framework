"""Secret scanner module."""

from src.scanners.secrets.scanner import SecretScanner
from src.scanners.secrets.patterns import SecretPattern, get_all_patterns
from src.scanners.secrets.entropy import calculate_entropy, is_high_entropy

__all__ = [
    "SecretScanner",
    "SecretPattern",
    "get_all_patterns",
    "calculate_entropy",
    "is_high_entropy",
]
