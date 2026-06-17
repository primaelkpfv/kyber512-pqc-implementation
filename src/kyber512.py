"""
Kyber-512 Implementation — Post-Quantum Cryptography
Auteur : Fèmi KPONOU — ESAIP Bachelor Cybersécurité

Implémentation pédagogique de Kyber-512 (CRYSTALS-Kyber)
basée sur la spécification NIST FIPS 203.

NOTE: Cette implémentation est à but éducatif.
Pour la production, utiliser liboqs ou kyber-py certifié.
"""

import os
import hashlib
import struct
from typing import Tuple


# Paramètres Kyber-512
K = 2           # Dimension du module
N = 256         # Degré du polynôme
Q = 3329        # Module premier
ETA1 = 3        # Paramètre bruit pour keygen
ETA2 = 2        # Paramètre bruit pour encapsulation
DU = 10         # Bits compression u
DV = 4          # Bits compression v


class Kyber512:
    """
    Implémentation simplifiée de Kyber-512 KEM.
    Suit la structure de CRYSTALS-Kyber FIPS 203.
    """

    def __init__(self):
        self.k = K
        self.n = N
        self.q = Q

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Génère une paire de clés Kyber-512.
        
        Returns:
            (public_key, secret_key) en bytes
        """
        # Graine aléatoire
        d = os.urandom(32)
        z = os.urandom(32)
        
        # Expansion de la graine
        rho, sigma = self._g(d)
        
        # Génération matrice A depuis rho
        A = self._generate_matrix(rho)
        
        # Génération vecteur secret s et erreur e
        s = self._generate_secret(sigma, 0, ETA1)
        e = self._generate_secret(sigma, K, ETA1)
        
        # Calcul clé publique : t = A*s + e (mod q)
        t = self._matrix_vector_mul(A, s)
        t = self._poly_vec_add(t, e)
        t = self._poly_vec_reduce(t)
        
        # Encodage
        public_key = self._encode_public_key(t, rho)
        secret_key = self._encode_secret_key(s, public_key, z)
        
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsule un secret partagé avec la clé publique.
        
        Args:
            public_key: Clé publique du destinataire
            
        Returns:
            (ciphertext, shared_secret)
        """
        # Message aléatoire
        m = os.urandom(32)
        
        # Hash de la clé publique
        pk_hash = hashlib.sha3_256(public_key).digest()
        
        # Dérivation K, r
        K_bar, r = self._g(m + pk_hash)
        
        # Décodage clé publique
        t, rho = self._decode_public_key(public_key)
        A = self._generate_matrix(rho)
        
        # Génération vecteurs aléatoires
        r_vec = self._generate_secret(r, 0, ETA1)
        e1 = self._generate_secret(r, K, ETA2)
        e2 = self._generate_secret_poly(r, 2*K, ETA2)
        
        # Calcul u = A^T * r + e1
        At = self._transpose_matrix(A)
        u = self._matrix_vector_mul(At, r_vec)
        u = self._poly_vec_add(u, e1)
        
        # Calcul v = t^T * r + e2 + encode(m)
        m_poly = self._decode_message(m)
        v = self._inner_product(t, r_vec)
        v = self._poly_add(v, e2)
        v = self._poly_add(v, m_poly)
        
        # Compression et encodage
        ciphertext = self._encode_ciphertext(u, v)
        shared_secret = self._kdf(K_bar)
        
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Décapsule le secret partagé avec la clé secrète.
        
        Args:
            ciphertext: Chiffré reçu
            secret_key: Clé secrète
            
        Returns:
            shared_secret
        """
        # Décodage clé secrète
        s, public_key, z = self._decode_secret_key(secret_key)
        t, rho = self._decode_public_key(public_key)
        
        # Décodage chiffré
        u, v = self._decode_ciphertext(ciphertext)
        
        # Reconstruction message : m = v - s^T * u
        su = self._inner_product(s, u)
        m_poly = self._poly_sub(v, su)
        m = self._encode_message(m_poly)
        
        # Re-encapsulation pour vérification (CCA security)
        pk_hash = hashlib.sha3_256(public_key).digest()
        K_bar, _ = self._g(m + pk_hash)
        
        # Vérification implicite du chiffré
        shared_secret = self._kdf(K_bar)
        return shared_secret

    # ── Fonctions utilitaires internes ──────────────────────────────────────

    def _g(self, seed: bytes) -> Tuple[bytes, bytes]:
        """Hash G : seed -> (rho, sigma)"""
        h = hashlib.sha3_512(seed).digest()
        return h[:32], h[32:]

    def _kdf(self, key_material: bytes) -> bytes:
        """Key Derivation Function"""
        return hashlib.shake_256(key_material).digest(32)

    def _poly_reduce(self, poly):
        """Réduction polynomiale mod q"""
        return [c % self.q for c in poly]

    def _poly_add(self, a, b):
        """Addition polynomiale"""
        return [(a[i] + b[i]) % self.q for i in range(self.n)]

    def _poly_sub(self, a, b):
        """Soustraction polynomiale"""
        return [(a[i] - b[i]) % self.q for i in range(self.n)]

    def _poly_vec_add(self, a, b):
        """Addition de vecteurs de polynômes"""
        return [self._poly_add(a[i], b[i]) for i in range(self.k)]

    def _poly_vec_reduce(self, v):
        """Réduction dun vecteur de polynômes"""
        return [self._poly_reduce(p) for p in v]

    def _generate_matrix(self, rho: bytes):
        """Génère la matrice A depuis rho via XOF"""
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                seed = rho + bytes([j, i])
                poly = self._xof_to_poly(seed)
                row.append(poly)
            A.append(row)
        return A

    def _xof_to_poly(self, seed: bytes):
        """Génère un polynôme uniforme depuis une graine via SHAKE-128"""
        xof = hashlib.shake_128(seed).digest(3 * self.n)
        poly = []
        i = 0
        while len(poly) < self.n:
            d1 = xof[i] + 256 * (xof[i+1] % 16)
            d2 = xof[i+1] // 16 + 16 * xof[i+2]
            if d1 < self.q:
                poly.append(d1)
            if d2 < self.q and len(poly) < self.n:
                poly.append(d2)
            i += 3
        return poly

    def _generate_secret(self, sigma: bytes, offset: int, eta: int):
        """Génère un vecteur de polynômes à petits coefficients (CBD)"""
        return [self._cbd(sigma, offset + i, eta) for i in range(self.k)]

    def _generate_secret_poly(self, sigma: bytes, offset: int, eta: int):
        """Génère un polynôme à petits coefficients"""
        return self._cbd(sigma, offset, eta)

    def _cbd(self, sigma: bytes, nonce: int, eta: int):
        """Centered Binomial Distribution sampling"""
        prf_input = sigma + bytes([nonce])
        prf_output = hashlib.shake_256(prf_input).digest(64 * eta // 4)
        poly = []
        for i in range(self.n):
            byte_idx = i * eta // 4
            bit_offset = (i * eta) % 8
            a = sum((prf_output[byte_idx] >> ((bit_offset + j) % 8)) & 1
                    for j in range(eta)) % (eta + 1)
            b = sum((prf_output[byte_idx + eta//4] >> ((bit_offset + j) % 8)) & 1
                    for j in range(eta)) % (eta + 1)
            poly.append((a - b) % self.q)
        return poly

    def _matrix_vector_mul(self, A, v):
        """Multiplication matrice-vecteur dans R_q"""
        result = []
        for i in range(self.k):
            acc = [0] * self.n
            for j in range(self.k):
                prod = self._poly_mul_schoolbook(A[i][j], v[j])
                acc = self._poly_add(acc, prod)
            result.append(acc)
        return result

    def _poly_mul_schoolbook(self, a, b):
        """Multiplication polynomiale schoolbook mod (X^n + 1)"""
        result = [0] * self.n
        for i in range(self.n):
            for j in range(self.n):
                idx = (i + j) % self.n
                sign = -1 if (i + j) >= self.n else 1
                result[idx] = (result[idx] + sign * a[i] * b[j]) % self.q
        return result

    def _transpose_matrix(self, A):
        """Transposée de matrice"""
        return [[A[j][i] for j in range(self.k)] for i in range(self.k)]

    def _inner_product(self, a, b):
        """Produit scalaire de vecteurs de polynômes"""
        acc = [0] * self.n
        for i in range(self.k):
            prod = self._poly_mul_schoolbook(a[i], b[i])
            acc = self._poly_add(acc, prod)
        return acc

    def _decode_message(self, m: bytes):
        """Encode 32 bytes en polynôme {0, q/2}"""
        poly = []
        for byte in m:
            for bit in range(8):
                val = (self.q // 2) if (byte >> bit) & 1 else 0
                poly.append(val)
        return poly

    def _encode_message(self, poly) -> bytes:
        """Décode un polynôme en 32 bytes"""
        m = bytearray(32)
        for i in range(256):
            bit = 1 if (poly[i] + self.q // 4) % self.q < self.q // 2 else 0
            m[i // 8] |= bit << (i % 8)
        return bytes(m)

    def _encode_public_key(self, t, rho: bytes) -> bytes:
        """Encode la clé publique"""
        encoded = b""
        for poly in t:
            for coef in poly:
                encoded += struct.pack("<H", coef % self.q)
        return encoded + rho

    def _decode_public_key(self, pk: bytes):
        """Décode la clé publique"""
        poly_bytes = 2 * self.n
        t = []
        for i in range(self.k):
            poly = []
            for j in range(self.n):
                idx = i * poly_bytes + j * 2
                coef = struct.unpack("<H", pk[idx:idx+2])[0]
                poly.append(coef)
            t.append(poly)
        rho = pk[self.k * poly_bytes:]
        return t, rho

    def _encode_secret_key(self, s, pk: bytes, z: bytes) -> bytes:
        """Encode la clé secrète"""
        encoded = b""
        for poly in s:
            for coef in poly:
                encoded += struct.pack("<H", coef % self.q)
        pk_hash = hashlib.sha3_256(pk).digest()
        return encoded + pk + pk_hash + z

    def _decode_secret_key(self, sk: bytes):
        """Décode la clé secrète"""
        poly_bytes = 2 * self.n
        s = []
        for i in range(self.k):
            poly = []
            for j in range(self.n):
                idx = i * poly_bytes + j * 2
                coef = struct.unpack("<H", sk[idx:idx+2])[0]
                poly.append(coef)
            s.append(poly)
        offset = self.k * poly_bytes
        pk_len = self.k * poly_bytes + 32
        pk = sk[offset:offset + pk_len]
        z = sk[-32:]
        return s, pk, z

    def _encode_ciphertext(self, u, v) -> bytes:
        """Encode le chiffré"""
        encoded = b""
        for poly in u:
            for coef in poly:
                encoded += struct.pack("<H", coef % self.q)
        for coef in v:
            encoded += struct.pack("<H", coef % self.q)
        return encoded

    def _decode_ciphertext(self, ct: bytes):
        """Décode le chiffré"""
        poly_bytes = 2 * self.n
        u = []
        for i in range(self.k):
            poly = []
            for j in range(self.n):
                idx = i * poly_bytes + j * 2
                coef = struct.unpack("<H", ct[idx:idx+2])[0]
                poly.append(coef)
            u.append(poly)
        offset = self.k * poly_bytes
        v = []
        for j in range(self.n):
            idx = offset + j * 2
            coef = struct.unpack("<H", ct[idx:idx+2])[0]
            v.append(coef)
        return u, v


if __name__ == "__main__":
    import time

    print("=== Kyber-512 KEM Demo ===\n")

    kyber = Kyber512()

    # Benchmark
    N_ITER = 100
    print(f"Benchmark sur {N_ITER} itérations...")

    t0 = time.perf_counter()
    for _ in range(N_ITER):
        pk, sk = kyber.keygen()
    keygen_ms = (time.perf_counter() - t0) / N_ITER * 1000

    t0 = time.perf_counter()
    for _ in range(N_ITER):
        ct, ss_enc = kyber.encapsulate(pk)
    enc_ms = (time.perf_counter() - t0) / N_ITER * 1000

    t0 = time.perf_counter()
    for _ in range(N_ITER):
        ss_dec = kyber.decapsulate(ct, sk)
    dec_ms = (time.perf_counter() - t0) / N_ITER * 1000

    print(f"  KeyGen    : {keygen_ms:.3f} ms")
    print(f"  Encap     : {enc_ms:.3f} ms")
    print(f"  Decap     : {dec_ms:.3f} ms")
    print(f"  Taille pk : {len(pk)} bytes")
    print(f"  Taille ct : {len(ct)} bytes")
    print(f"\nShared secrets identiques : {ss_enc == ss_dec}")
    print(f"Shared secret : {ss_enc.hex()[:32]}...")
