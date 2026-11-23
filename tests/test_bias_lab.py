from src.bias_audit import audit_statistical_bias, SECP256K1_N
from src.entropy_analysis import calculate_shannon_entropy, calculate_uniqueness_ratio
from src.cve_2013_7372_scanner import filter_cve_targets

def test_statistical_bias_audit():
    sample_matrix = [
        (0x123456789, 0x987654321, 0xABCDEF),
        (0x23456789A, 0x876543219, 0xBCDEFA),
        (0x3456789AB, 0x765432198, 0xCDEFAB)
    ]
    res = audit_statistical_bias(sample_matrix)
    assert res["count"] == 3
    assert 0.0 <= res["mean"] <= 1.0
    assert "variance" in res

def test_shannon_entropy():
    uniform_bytes = bytes(range(256))
    ent = calculate_shannon_entropy(uniform_bytes)
    assert abs(ent - 8.0) < 0.01

    constant_bytes = b'\x00' * 100
    ent_const = calculate_shannon_entropy(constant_bytes)
    assert ent_const == 0.0

def test_cve_filter():
    targets = [
        {"address": "1Test1", "spend_count": 80, "anomaly_ratio": 0.99, "android_bug_window_count": 10},
        {"address": "1Test2", "spend_count": 10, "anomaly_ratio": 0.40, "android_bug_window_count": 0}
    ]
    flagged = filter_cve_targets(targets, min_spend_count=50, min_anomaly_ratio=0.95)
    assert len(flagged) == 1
    assert flagged[0]["address"] == "1Test1"
