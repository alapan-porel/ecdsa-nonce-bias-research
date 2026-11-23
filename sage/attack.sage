import json
from sage.all import *

# Load the verified data
with open('funded_sigs_with_z.json', 'r') as f:
    data = json.load(f)

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_hnp(sigs, bits_leaked):
    m = len(sigs)
    X = 2^bits_leaked
    M = Matrix(ZZ, m + 2, m + 2)
    
    for i in range(m):
        r = int(sigs[i]['r_hex'], 16)
        s = int(sigs[i]['s_hex'], 16)
        z = int(sigs[i]['z_dec'])
        
        inv_s = inverse_mod(s, n)
        
        M[i, i] = n
        M[m, i] = (r * inv_s) % n
        M[m + 1, i] = (z * inv_s) % n
        
    M[m, m] = 1
    M[m + 1, m + 1] = n
    return M.LLL()

target = data[0]
print(f"Targeting: {target['address']}")
sigs = target['sigs']

# Test bias: 4, 8, 12, 16 bits
for bias in [4, 8, 12, 16]:
    print(f"Testing bias: {bias} bits...")
    try:
        reduced = solve_hnp(sigs[:60], bias)
        print(reduced[0])
    except Exception as e:
        print(f"Error: {e}")
