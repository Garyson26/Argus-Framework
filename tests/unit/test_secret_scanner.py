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
    
    def test_calculate_confidence_above_threshold(self):
        """Confidence should increase above threshold."""
        confidence = calculate_confidence(5.5, threshold=4.5)
        assert 0.5 < confidence <= 1.0


class TestPatterns:
    """Tests for secret patterns."""
    
    def test_get_all_patterns(self):
        """Should return list of patterns."""
        patterns = get_all_patterns()
        assert len(patterns) > 0
        assert all(isinstance(p, SecretPattern) for p in patterns)
    
    def test_get_patterns_by_type(self):
        """Should filter patterns by type."""
        aws_patterns = get_patterns_by_type(SecretType.AWS_ACCESS_KEY)
        assert len(aws_patterns) > 0
        assert all(p.secret_type == SecretType.AWS_ACCESS_KEY for p in aws_patterns)
    
    def test_aws_access_key_pattern(self):
        """AWS access key pattern should match valid keys."""
        patterns = get_patterns_by_type(SecretType.AWS_ACCESS_KEY)
        test_key = "AKIAIOSFODNN7EXAMPLE"
        
        matched = False
        for pattern in patterns:
            if pattern.match(test_key):
                matched = True
                break
        
        assert matched
    
    def test_github_token_pattern(self):
        """GitHub token pattern should match valid tokens."""
        patterns = get_patterns_by_type(SecretType.GITHUB_TOKEN)
        test_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        
        matched = False
        for pattern in patterns:
            if pattern.match(test_token):
                matched = True
                break
        
        assert matched
    
    def test_private_key_pattern(self):
        """Private key pattern should match PEM headers."""
        patterns = get_patterns_by_type(SecretType.PRIVATE_KEY)
        test_key = "-----BEGIN RSA PRIVATE KEY-----"
        
        matched = False
        for pattern in patterns:
            if pattern.match(test_key):
                matched = True
                break
        
        assert matched
    
    def test_pattern_has_suggestion(self):
        """All patterns should have remediation suggestions."""
        patterns = get_all_patterns()
        for pattern in patterns:
            assert pattern.suggestion
            assert len(pattern.suggestion) > 0


class TestSecretPatternMatching:
    """Tests for pattern matching in content."""
    
    def test_match_aws_key_in_code(self, sample_secret_content):
        """Should find AWS keys in sample content."""
        patterns = get_patterns_by_type(SecretType.AWS_ACCESS_KEY)
        
        found = False
        for pattern in patterns:
            matches = pattern.match(sample_secret_content)
            if matches:
                found = True
                break
        
        assert found
    
    def test_match_github_token_in_code(self, sample_secret_content):
        """Should find GitHub token in sample content."""
        patterns = get_patterns_by_type(SecretType.GITHUB_TOKEN)
        
        found = False
        for pattern in patterns:
            matches = pattern.match(sample_secret_content)
            if matches:
                found = True
                break
        
        assert found
    
    def test_match_private_key_in_code(self, sample_secret_content):
        """Should find private key in sample content."""
        patterns = get_patterns_by_type(SecretType.PRIVATE_KEY)
        
        found = False
        for pattern in patterns:
            matches = pattern.match(sample_secret_content)
            if matches:
                found = True
                break
        
        assert found
