import os
import sys
import json
from sage.all import *

# Default to synthetic test vectors fixture
DEFAULT_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic_biased_signatures.json")
data_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATA_PATH

if not os.path.exists(data_path):
    print(f"Dataset path not found: {data_path}")
    sys.exit(1)

with open(data_path, 'r') as f:
    raw_data = json.load(f)

# Support both flat vector lists and address-grouped dicts
sigs = raw_data[0]['sigs'] if isinstance(raw_data, list) and 'sigs' in raw_data[0] else raw_data

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_hnp(sigs, bits_leaked):
    """
    Constructs the Boneh-Venkatesan Hidden Number Problem (HNP) lattice:
    BVP reduction to Closest Vector Problem (CVP) / Shortest Vector Problem (SVP).
    """
    m = min(len(sigs), 60)
    X = 2^bits_leaked
    M = Matrix(ZZ, m + 2, m + 2)
    
    for i in range(m):
        r = int(sigs[i]['r_hex'], 16)
        s = int(sigs[i]['s_hex'], 16)
        z = int(sigs[i]['z_dec']) if 'z_dec' in sigs[i] else int(sigs[i]['z_hex'], 16)
        
        inv_s = inverse_mod(s, n)
        
        M[i, i] = n
        M[m, i] = (r * inv_s) % n
        M[m + 1, i] = (z * inv_s) % n
        
    M[m, m] = 1
    M[m + 1, m + 1] = n
    return M.LLL()

print(f"Loaded {len(sigs)} signatures for HNP lattice reduction.")

# Test bias across 4, 8, 12, 16 bits
for bias in [4, 8, 12, 16]:
    print(f"Testing bias: {bias} bits...")
    try:
        reduced = solve_hnp(sigs, bias)
        print(f"Reduced basis first row vector: {reduced[0][:5]}...")
    except Exception as e:
        print(f"Error: {e}")
