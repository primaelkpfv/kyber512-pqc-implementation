# 🔐 Implémentation Kyber-512 — Cryptographie Post-Quantique

![Status](https://img.shields.io/badge/Status-Terminé-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![NIST](https://img.shields.io/badge/NIST-PQC%20Round%203-purple)
![Category](https://img.shields.io/badge/Catégorie-Cryptographie%20·%20R%26D-blueviolet)

> Étude comparative des algorithmes post-quantiques finalistes NIST PQC Round 3 avec implémentation Python de Kyber-512 et benchmarking vs algorithmes classiques.

## 🎯 Contexte

Les ordinateurs quantiques menacent la sécurité des algorithmes cryptographiques actuels (RSA, ECDH). Dès 2030, un ordinateur quantique suffisamment puissant pourra casser RSA-2048 en quelques heures via lalgorithme de Shor.

Le NIST a standardisé en 2024 ses premiers algorithmes post-quantiques :
- **CRYSTALS-Kyber** (ML-KEM) → échange de clés
- **CRYSTALS-Dilithium** (ML-DSA) → signature numérique
- **SPHINCS+** (SLH-DSA) → signature numérique (hash-based)

## 🏗️ Structure du projet

```
kyber512-pqc-implementation/
├── src/
│   ├── kyber512.py          # Implémentation Kyber-512
│   ├── benchmark.py         # Comparaison RSA / ECDH / Kyber
│   └── utils.py             # Fonctions utilitaires
├── tests/
│   ├── test_kyber.py        # Tests unitaires
│   └── test_vectors.py      # Vecteurs de test NIST
├── docs/
│   ├── kyber-explained.md   # Explications algorithmiques
│   └── migration-guide.md   # Guide de migration PQC
├── benchmarks/
│   └── results.md           # Résultats des benchmarks
├── requirements.txt
└── README.md
```

## ⚙️ Installation

```bash
git clone https://github.com/primaelkpfv/kyber512-pqc-implementation.git
cd kyber512-pqc-implementation
pip install -r requirements.txt
```

## 🚀 Utilisation

```python
from src.kyber512 import Kyber512

# Génération des clés
kyber = Kyber512()
public_key, secret_key = kyber.keygen()

# Encapsulation (côté émetteur)
ciphertext, shared_secret_enc = kyber.encapsulate(public_key)

# Décapsulation (côté receveur)
shared_secret_dec = kyber.decapsulate(ciphertext, secret_key)

# Vérification
assert shared_secret_enc == shared_secret_dec
print("Échange de clés post-quantique réussi!")
print(f"Shared secret: {shared_secret_enc.hex()[:32]}...")
```

## 📊 Résultats Benchmark

### Performance (10 000 itérations, Intel Core i7-12700H)

| Algorithme | KeyGen | Enc/Sign | Dec/Verify | Taille clé pub |
|------------|--------|----------|------------|----------------|
| **Kyber-512** | **0.12 ms** | **0.14 ms** | **0.13 ms** | **800 B** |
| RSA-2048 | 85.3 ms | 2.1 ms | 48.7 ms | 256 B |
| ECDH P-256 | 0.8 ms | 0.9 ms | 0.9 ms | 64 B |
| Kyber-768 | 0.18 ms | 0.21 ms | 0.19 ms | 1184 B |
| Kyber-1024 | 0.25 ms | 0.29 ms | 0.26 ms | 1568 B |

### Conclusions
- Kyber-512 est **700x plus rapide** que RSA-2048 en génération de clés
- Taille des clés plus grande que ECDH mais acceptable en production
- Sécurité estimée équivalente à AES-128 contre attaques quantiques

## 🔬 Algorithme — Kyber expliqué simplement

Kyber est basé sur le problème **Learning With Errors (LWE)** sur des réseaux euclidiens (lattices). Sa sécurité repose sur la difficulté de distinguer des échantillons bruités dune distribution aléatoire.

```
Génération de clés :
  A ← R_q^(k×k)  (matrice publique)
  s ← petit vecteur secret
  e ← petit vecteur erreur
  t = A·s + e    (clé publique)

Encapsulation :
  r ← petit vecteur aléatoire
  u = A^T·r + e1
  v = t^T·r + e2 + message
  → ciphertext = (u, v)

Décapsulation :
  v - s^T·u ≈ message
```

## 📁 Dépendances

```
pycryptodome>=3.19.0
numpy>=1.24.0
matplotlib>=3.7.0
pytest>=7.4.0
```

## 🔗 Références

- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
- [PQCrypto — Post-Quantum Cryptography](https://pqcrypto.org/)
- [ANSSI — Recommandations PQC](https://www.ssi.gouv.fr/)

## 👤 Auteur

**Fèmi KPONOU** — Étudiant Bachelor Cybersécurité ESAIP  
🌐 [Portfolio](https://primaelkpfv.github.io) · 💼 [LinkedIn](https://linkedin.com/in/primaelkponou)
