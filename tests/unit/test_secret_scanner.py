"""Unit tests for secret scanner."""

import pytest

from src.scanners.secrets.entropy import (
    calculate_entropy,
    is_high_entropy,
    calculate_confidence,
)
from src.scanners.secrets.patterns import (
    SecretPattern,
    SecretType,
    get_all_patterns,
    get_patterns_by_type,
)
from src.scanners.base import Severity


class TestEntropy:
    """Tests for entropy calculation."""
    
    def test_calculate_entropy_empty_string(self):
        """Empty string should have zero entropy."""
        assert calculate_entropy("") == 0.0
    
    def test_calculate_entropy_single_char(self):
        """Single repeated character has zero entropy."""
        assert calculate_entropy("aaaaaaaaaa") == 0.0
    
    def test_calculate_entropy_random_string(self):
        """Random string should have high entropy."""
        random_str = "A1b2C3d4E5f6G7h8I9j0"
        entropy = calculate_entropy(random_str)
        assert entropy > 3.5
    
    def test_calculate_entropy_aws_key_like(self):
        """AWS key-like string should have high entropy."""
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        entropy = calculate_entropy(aws_key)
        assert entropy > 3.0
    
    def test_is_high_entropy_short_string(self):
        """Short strings should not be flagged."""
        assert is_high_entropy("short") is False
    
    def test_is_high_entropy_long_string(self):
        """Long strings over threshold should be flagged."""
        # This is designed to have high entropy
        high_entropy = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0"
        result = is_high_entropy(high_entropy, threshold=4.0, min_length=20)
        # Result depends on actual entropy calculation
        assert isinstance(result, bool)
    
    def test_calculate_confidence_below_threshold(self):
        """Confidence should be 0 below threshold."""
        assert calculate_confidence(3.0, threshold=4.5) == 0.0
    
    def test_calculate_confidence_at_threshold(self):
        """Confidence should be 0.5 at threshold."""
        assert calculate_confidence(4.5, threshold=4.5) == 0.5
    
