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
        
