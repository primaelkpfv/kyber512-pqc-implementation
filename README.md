# Kyber-512 Post-Quantum Cryptography

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Status](https://img.shields.io/badge/Status-Complete-success)
![NIST](https://img.shields.io/badge/Standard-NIST%20FIPS%20203-orange)
![License](https://img.shields.io/badge/License-MIT-green)

Implementation pedagogique de CRYSTALS-Kyber-512 avec benchmarking comparatif versus RSA-2048 et ECDH P-256. Rapport technique 30 pages sur la migration post-quantique.

---

## Contexte

Les ordinateurs quantiques menacent RSA et ECDH via l'algorithme de Shor. Le NIST a standardise en 2024 **CRYSTALS-Kyber** (ML-KEM, FIPS 203) comme algorithme KEM post-quantique. Ce projet implemente et benchmark Kyber-512 pour analyser les implications pratiques.

---

## Algorithmes Compares

| Algorithme | Securite classique | Securite quantique | Cle publique |
|------------|-------------------|-------------------|--------------|
| RSA-2048 | 112 bits | Vulnerable (Shor) | 256 B |
| ECDH P-256 | 128 bits | Vulnerable (Shor) | 64 B |
| **Kyber-512** | **128 bits** | **Resiste (LWE)** | **800 B** |

---

## Installation & Usage

```bash
git clone https://github.com/primaelkpfv/kyber512-pqc-implementation
cd kyber512-pqc-implementation
pip install -r requirements.txt

# Demo interactive
python3 src/kyber512_demo.py

# Benchmarking complet
python3 benchmarks/benchmark_comparison.py

# Tests unitaires
python3 -m pytest tests/ -v
```

---

## Resultats Benchmarking

Moyenne sur 1000 iterations (Intel i7-1165G7) :

| Operation | RSA-2048 | ECDH P-256 | Kyber-512 |
|-----------|----------|------------|-----------|
| Keygen | 12.4 ms | 0.8 ms | **0.18 ms** |
| Encapsulation | 0.9 ms | 1.2 ms | **0.22 ms** |
| Decapsulation | 8.7 ms | 1.1 ms | **0.25 ms** |
| **Total** | **22.0 ms** | **3.1 ms** | **0.65 ms** |

Kyber-512 est **33x plus rapide** que RSA-2048 avec resistance quantique.

---

## Parametres Kyber-512

```python
N    = 256   # Degre polynome
Q    = 3329  # Module premier
K    = 2     # Dimension vecteur (k=2 => Kyber-512)
eta1 = 3     # CBD keygen
eta2 = 2     # CBD encryption
du   = 10    # Bits compression u
dv   = 4     # Bits compression v
```

---

## Structure du Projet

```
kyber512-pqc-implementation/
├── src/
│   ├── kyber512.py           # Implementation KEM (keygen/encap/decap)
│   ├── ntt.py                # Number Theoretic Transform
│   ├── polyvec.py            # Operations vecteurs polynomes
│   └── kyber512_demo.py      # Demo interactive
├── benchmarks/
│   ├── benchmark_comparison.py
│   └── results/
│       └── benchmark_results.json
├── tests/
│   ├── test_kyber.py
│   └── test_ntt.py
├── docs/
│   └── rapport-pqc-migration.md
├── requirements.txt
└── README.md
```

---

## References

- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
- [PQCrypto](https://pqcrypto.org)
- [Portfolio Femi KPONOU](https://primaelkpfv.github.io)

---
*Projet Bachelor Cybersecurite - ESAIP 2025 | Rapport 30 pages disponible sur demande*
