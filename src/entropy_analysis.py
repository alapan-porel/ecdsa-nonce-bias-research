"""
Nonce Entropy Analysis Suite
"""

import math
from typing import List

def calculate_shannon_entropy(byte_seq: bytes) -> float:
    if not byte_seq:
        return 0.0
    counts = {}
    for b in byte_seq:
        counts[b] = counts.get(b, 0) + 1
    total = len(byte_seq)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def calculate_uniqueness_ratio(r_values_hex: List[str]) -> float:
    if not r_values_hex:
        return 1.0
    return len(set(r_values_hex)) / len(r_values_hex)
