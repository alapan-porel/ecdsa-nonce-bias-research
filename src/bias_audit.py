"""
ECDSA Nonce Statistical Bias Auditor
Audits the statistical distribution of (r * s^-1) mod N across signature sets.
Detects low-entropy bias for the Hidden Number Problem (HNP).
"""

import math
from typing import List, Tuple, Dict, Any

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def audit_statistical_bias(matrix: List[Tuple[int, int, int]]) -> Dict[str, Any]:
    """
    matrix: list of tuples (r, s, z)
    Evaluates distribution of (r * s^-1) mod N scaled to [0.0, 1.0].
    Theoretical uniform: mean = 0.5, variance = 1/12 (~0.08333)
    """
    if not matrix:
        return {"count": 0, "mean": 0.0, "variance": 0.0, "bias_detected": False}

    normalized_vals = []
    for r, s, z in matrix:
        s_inv = pow(s, -1, SECP256K1_N)
        val = (r * s_inv) % SECP256K1_N
        normalized_vals.append(val / SECP256K1_N)

    count = len(normalized_vals)
    mean = sum(normalized_vals) / count
    variance = sum((x - mean) ** 2 for x in normalized_vals) / count

    theoretical_variance = 1.0 / 12.0
    var_deviation = abs(variance - theoretical_variance) / theoretical_variance

    # If variance deviates significantly from uniform, flag bias
    bias_detected = var_deviation > 0.15 or abs(mean - 0.5) > 0.05

    return {
        "count": count,
        "mean": round(mean, 6),
        "variance": round(variance, 6),
        "theoretical_variance": round(theoretical_variance, 6),
        "variance_deviation_pct": round(var_deviation * 100, 2),
        "bias_detected": bias_detected
    }
