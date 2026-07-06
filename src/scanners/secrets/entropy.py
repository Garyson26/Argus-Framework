"""
Shannon entropy calculation for secret detection.

High-entropy strings are likely to be secrets, API keys, or other sensitive data.
"""

import math
import string
from typing import Optional


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Higher entropy indicates more randomness, which is characteristic of
    secrets, API keys, and other sensitive credentials.
    
    Args:
        data: String to calculate entropy for
        
    Returns:
        Shannon entropy value (0.0 to ~4.7 for typical text)
    """
    if not data:
        return 0.0
    
    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    length = len(data)
    entropy = 0.0
    
    for count in freq.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    
    return entropy


def is_high_entropy(
    data: str,
    threshold: float = 4.5,
    min_length: int = 20,
    max_length: int = 200,
) -> bool:
    """
    Check if a string has high entropy (likely a secret).
    
    Args:
        data: String to check
        threshold: Entropy threshold (default 4.5)
        min_length: Minimum string length to consider
        max_length: Maximum string length to consider
        
    Returns:
        True if string has high entropy
    """
    # Skip strings that are too short or too long
    if len(data) < min_length or len(data) > max_length:
        return False
    
    # Skip strings that are clearly not secrets
    if _is_likely_not_secret(data):
        return False
    
    entropy = calculate_entropy(data)
    return entropy >= threshold


def _is_likely_not_secret(data: str) -> bool:
    """
    Heuristics to filter out strings that look high-entropy but aren't secrets.
    
    Args:
        data: String to check
        
    Returns:
        True if string is likely NOT a secret
    """
    data_lower = data.lower()
    
    # Common false positives
    false_positive_indicators = [
        # UUIDs (high entropy but not secrets)
        lambda s: s.count('-') == 4 and len(s) == 36,
        # Hashes that are likely checksums, not secrets
        lambda s: len(s) in (32, 40, 64, 128) and all(c in '0123456789abcdef' for c in s.lower()),
        # Base64 encoded common strings
        lambda s: s.endswith('==') and len(s) < 30,
        # File paths
        lambda s: '/' in s and s.count('/') > 2,
        # URLs without credentials
        lambda s: s.startswith(('http://', 'https://')) and '@' not in s,
        # Package versions
        lambda s: s.count('.') >= 2 and all(c in '0123456789.' for c in s),
    ]
    
    for check in false_positive_indicators:
        try:
            if check(data):
                return True
        except Exception:
            pass
    
    # Check character distribution - secrets usually have mixed case and digits
    has_upper = any(c in string.ascii_uppercase for c in data)
    has_lower = any(c in string.ascii_lowercase for c in data)
    has_digit = any(c in string.digits for c in data)
    
    # If it's all one type, probably not a secret
    if sum([has_upper, has_lower, has_digit]) < 2:
        return True
    
    return False


def find_high_entropy_strings(
    text: str,
    threshold: float = 4.5,
    min_length: int = 20,
    max_length: int = 200,
) -> list[dict]:
    """
    Find high-entropy strings in text.
    
    Args:
        text: Text to search
        threshold: Entropy threshold
        min_length: Minimum string length
        max_length: Maximum string length
        
    Returns:
        List of dicts with 'value', 'entropy', 'start', 'end'
    """
    results = []
    
    # Split text into potential secret tokens
    # Look for strings that could be secrets (alphanumeric with special chars)
    import re
    
    # Pattern for potential secrets
    pattern = r'[A-Za-z0-9+/=_\-]{' + str(min_length) + ',' + str(max_length) + '}'
    
    for match in re.finditer(pattern, text):
        value = match.group()
        
        if is_high_entropy(value, threshold, min_length, max_length):
            entropy = calculate_entropy(value)
            results.append({
                'value': value,
                'entropy': entropy,
                'start': match.start(),
                'end': match.end(),
            })
    
    return results


def calculate_confidence(
    entropy: float,
    threshold: float = 4.5,
    max_entropy: float = 6.0,
) -> float:
    """
    Calculate confidence score based on entropy.
    
    Args:
        entropy: Calculated entropy value
        threshold: Minimum entropy threshold
        max_entropy: Maximum expected entropy
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    if entropy < threshold:
        return 0.0
    
    # Scale confidence from 0.5 at threshold to 1.0 at max_entropy
    normalized = (entropy - threshold) / (max_entropy - threshold)
    confidence = 0.5 + (normalized * 0.5)
    
    return min(1.0, max(0.0, confidence))
