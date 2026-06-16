#!/usr/bin/env python3
# Tests unitaires Kyber-512
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__),'..','src'))
from kyber512 import Kyber512, hash_g, hash_h, ntt, inv_ntt, N, Q
import random

def test_keygen_sizes():
    pk,sk=Kyber512().keygen()
    assert len(pk)==800 and len(sk)==1632
    print("  [OK] test_keygen_sizes")

def test_encapsulate_sizes():
    k=Kyber512(); pk,sk=k.keygen(); ct,ss=k.encapsulate(pk)
    assert len(ct)==768 and len(ss)==32
    print("  [OK] test_encapsulate_sizes")

def test_ntt_inverse():
    poly=[random.randint(0,Q-1) for _ in range(N)]
    assert inv_ntt(ntt(poly))==poly
    print("  [OK] test_ntt_inverse")

def test_hash_g():
    a,b=hash_g(b"kyber_test"); assert len(a)==32 and len(b)==32
    print("  [OK] test_hash_g")

if __name__=="__main__":
    print("Running Kyber-512 tests...")
    test_keygen_sizes(); test_encapsulate_sizes()
    test_ntt_inverse(); test_hash_g()
    print("\nAll tests passed!")
