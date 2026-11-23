"""
Android SecureRandom Bug Window Scanner (CVE-2013-7372)
Filters blockchain signatures for characteristic low-entropy nonce anomalies.
"""

from typing import List, Dict, Any

def filter_cve_targets(
    records: List[Dict[str, Any]],
    min_spend_count: int = 50,
    min_anomaly_ratio: float = 0.95
) -> List[Dict[str, Any]]:
    flagged = []
    for r in records:
        spend = r.get("spend_count", 0)
        anomaly = r.get("anomaly_ratio", 0.0)
        android_bugs = r.get("android_bug_window_count", 0)

        if spend >= min_spend_count and anomaly >= min_anomaly_ratio and android_bugs > 0:
            flagged.append(r)

    flagged.sort(key=lambda x: x.get("anomaly_ratio", 0.0), reverse=True)
    return flagged
