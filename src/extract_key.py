"""
Lattice Candidate Private Key Verifier
Audits CVP/LLL reduction candidate vectors against public key commitments.
Supports both Python 'cryptography' (standard) and 'ecdsa' backends.
"""

import sys
import binascii
from typing import Optional, List

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Try importing cryptography first, fallback to ecdsa
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from ecdsa import SECP256k1, SigningKey
    HAS_ECDSA = True
except ImportError:
    HAS_ECDSA = False

def derive_uncompressed_pubkey(private_key_int: int) -> Optional[str]:
    """Derives 65-byte uncompressed SECP256k1 public key hex ('04...') from private key scalar."""
    if not (1 <= private_key_int < SECP256K1_N):
        return None

    if HAS_CRYPTOGRAPHY:
        try:
            sk = ec.derive_private_key(private_key_int, ec.SECP256K1())
            raw_pub = sk.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            return binascii.hexlify(raw_pub).decode('ascii')
        except Exception:
            pass

    if HAS_ECDSA:
        try:
            sk = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
            vk = sk.get_verifying_key()
            return "04" + binascii.hexlify(vk.to_string()).decode('ascii')
        except Exception:
            pass

    return None

def verify_candidate_scalar(val: int, target_pubkey_hex: str) -> bool:
    """Verifies whether scalar or its modular complement matches the target public key."""
    val = abs(val) % SECP256K1_N
    if val <= 1:
        return False

    derived = derive_uncompressed_pubkey(val)
    if derived and derived.lower() == target_pubkey_hex.lower():
        print(f"\n[+] SUCCESS: Private Key Found: {hex(val)}")
        return True

    # Test modular complement (s-negation)
    comp = (SECP256K1_N - val) % SECP256K1_N
    derived_comp = derive_uncompressed_pubkey(comp)
    if derived_comp and derived_comp.lower() == target_pubkey_hex.lower():
        print(f"\n[+] SUCCESS: Private Key Found (Complement): {hex(comp)}")
        return True

    return False

def scan_candidate_matrix(candidate_rows: List[List[int]], target_pubkey_hex: str) -> Optional[int]:
    """Scans rows of lattice reduction candidate coordinates for valid private key."""
    for row_idx, row in enumerate(candidate_rows):
        for col_idx, c in enumerate(row):
            if verify_candidate_scalar(c, target_pubkey_hex):
                return abs(c) % SECP256K1_N
    return None

if __name__ == "__main__":
    # Synthetic verification vector
    # Private Key: 0x5a1f09b8c3d2e1f4a5b6c7d8e9f0123456789abcdef0123456789abcdef01234
    sample_target_pubkey = derive_uncompressed_pubkey(0x5a1f09b8c3d2e1f4a5b6c7d8e9f0123456789abcdef0123456789abcdef01234)
    print(f"Sample Target PubKey: {sample_target_pubkey}")

    candidate_rows = [
        [0x12345, 0x5a1f09b8c3d2e1f4a5b6c7d8e9f0123456789abcdef0123456789abcdef01234, 0x99999]
    ]

    if sample_target_pubkey:
        print("Auditing candidate vectors against target public key...")
        res = scan_candidate_matrix(candidate_rows, sample_target_pubkey)
        if res:
            print(f"Audit verified successfully: key recovered = {hex(res)}")
        else:
            print("No matching scalar in candidate set.")
