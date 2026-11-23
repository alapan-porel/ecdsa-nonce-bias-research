# ECDSA Nonce Bias Laboratory & Hidden Number Problem (HNP) Lattice Reductions

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![SageMath](https://img.shields.io/badge/Lattice-SageMath%20LLL%2FBabai-purple.svg)](https://www.sagemath.org/)

A specialized cryptographic research laboratory analyzing statistical pseudo-random number generator (PRNG) failures in SECP256k1 signatures, including historical Android Java `SecureRandom` flaw windows (`CVE-2013-7372`), $(r \cdot s^{-1}) \pmod N$ distribution anomalies, and SageMath LLL/Babai Closest Vector Problem (CVP) lattice formulations for the Hidden Number Problem (HNP).

---

## Mathematical Formulation: The Hidden Number Problem (HNP)

Let an ECDSA signature be $(r_i, s_i)$ generated with message hash $z_i$ and private key $d$:
$$s_i \equiv k_i^{-1} (z_i + r_i \cdot d) \pmod N$$

Rearranging for the unknown nonce $k_i$:
$$k_i \equiv s_i^{-1} z_i + s_i^{-1} r_i \cdot d \pmod N$$

Let $t_i = s_i^{-1} r_i \pmod N$ and $u_i = s_i^{-1} z_i \pmod N$. Then:
$$k_i \equiv t_i \cdot d + u_i \pmod N$$

If $k_i$ is biased (for example, the top $\ell$ bits are known to be zero such that $|k_i| < N / 2^\ell$), this instance maps directly to Boneh-Venkatesan's Hidden Number Problem.

### Lattice Basis Matrix Construction

Given $m$ biased signatures, we construct an $(m+2) \times (m+2)$ integer lattice basis $L$:

$$L = \begin{pmatrix}
N & 0 & \dots & 0 & 0 & 0 \\
0 & N & \dots & 0 & 0 & 0 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots \\
0 & 0 & \dots & N & 0 & 0 \\
t_1 & t_2 & \dots & t_m & \frac{2^\ell}{N} & 0 \\
u_1 & u_2 & \dots & u_m & 0 & 2^\ell
\end{pmatrix}$$

Applying the Lenstra-Lenstra-Lovász (LLL) lattice reduction algorithm solves for short vectors containing the secret key $d$.

---

## Android PRNG Failure (CVE-2013-7372)

In August 2013, an implementation flaw was disclosed in the Android Java cryptographic provider (`libcore.crypto`). `SecureRandom` failed to properly initialize the underlying OpenSSL PRNG seed from `/dev/urandom`, causing multiple Bitcoin mobile wallets to produce identical or low-entropy nonces across consecutive transactions.

---

## Installation & Running Tests

```bash
pip install -r requirements.txt
pytest tests/
```

### SageMath LLL Execution

```bash
sage sage/attack.sage
```

---

## Synthetic Test Fixtures

* `fixtures/strike_matrix_sample.json`: Synthetic $(r, s, z)$ matrix verifying modular statistical metrics.
* `fixtures/synthetic_biased_signatures.json`: Controlled test vectors with known $\ell$-bit leakage.
* Live addresses and funded targets are strictly excluded.

---

## License

Apache-2.0. Cleanroom extraction and packaging release.
