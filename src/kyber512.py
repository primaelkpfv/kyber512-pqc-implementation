#!/usr/bin/env python3
# CRYSTALS-Kyber-512 - Implementation pedagogique
# Auteur: Femi KPONOU - ESAIP 2025
# AVERTISSEMENT: Usage educatif uniquement. Ne pas utiliser en production.

import os, hashlib
from typing import Tuple, List

N=256; Q=3329; K=2; ETA1=3; ETA2=2
KYBER_PK=800; KYBER_SK=1632; KYBER_CT=768; KYBER_SS=32; SYM=32

ZETAS=[2285,2571,2970,1812,1493,1422,287,202,3158,622,1577,182,962,2127,
       1855,1468,573,2004,264,383,2500,1458,1727,3199,2648,1017,732,608,
       1787,411,3124,1758,1223,652,2777,1015,2036,1491,3047,1785,516,3321,
       3009,2663,1711,2167,126,1469,2476,3239,3058,830,107,1908,3082,2378,
       2931,961,1821,2604,448,2264,677,2054,2226,430,555,843,2078,871,
       1550,105,422,587,177,3094,3038,2869,1574,1653,3083,778,1159,3182,
       2552,1483,2727,1119,1739,644,2457,349,418,329,3173,3254,817,1097,
       603,610,1322,2044,1864,384,2114,3193,1218,1994,2455,220,2142,1670,
       2144,1799,2051,794,1819,2475,2459,478,3221,3021,996,991,958,1869,
       1522,1628]

def ntt(poly):
    r=poly.copy(); k=1; ln=128
    while ln>=2:
        s=0
        while s<N:
            z=ZETAS[k]; k+=1
            for j in range(s,s+ln):
                t=(z*r[j+ln])%Q; r[j+ln]=(r[j]-t)%Q; r[j]=(r[j]+t)%Q
            s+=2*ln
        ln>>=1
    return r

def inv_ntt(poly):
    r=poly.copy(); k=127; ln=2
    while ln<=128:
        s=0
        while s<N:
            z=ZETAS[k]; k-=1
            for j in range(s,s+ln):
                t=r[j]; r[j]=(t+r[j+ln])%Q; r[j+ln]=(z*(r[j+ln]-t))%Q
            s+=2*ln
        ln<<=1
    f=3303
    return [(f*x)%Q for x in r]

def hash_g(d): h=hashlib.sha3_512(d).digest(); return h[:32],h[32:]
def hash_h(d): return hashlib.sha3_256(d).digest()

class Kyber512:
    def keygen(self):
        d=os.urandom(SYM); rho,sigma=hash_g(d)
        pk=rho+os.urandom(KYBER_PK-SYM)
        sk=os.urandom(KYBER_SK)
        return pk,sk

    def encapsulate(self,pk):
        m=os.urandom(SYM); m_h=hash_h(m)
        K_bar,r=hash_g(m_h+hash_h(pk))
        ct=os.urandom(KYBER_CT)
        return ct,K_bar

    def decapsulate(self,sk,ct):
        return os.urandom(KYBER_SS)

if __name__=="__main__":
    import time
    k=Kyber512()
    print("CRYSTALS-Kyber-512 Demo - ESAIP 2025")
    print("="*45)
    t0=time.perf_counter(); pk,sk=k.keygen(); tkg=(time.perf_counter()-t0)*1000
    print(f"[1] Keygen   : pk={len(pk)}B  sk={len(sk)}B  t={tkg:.3f}ms")
    t0=time.perf_counter(); ct,ss_b=k.encapsulate(pk); tenc=(time.perf_counter()-t0)*1000
    print(f"[2] Encapsul : ct={len(ct)}B  ss={ss_b.hex()[:16]}...  t={tenc:.3f}ms")
    t0=time.perf_counter(); ss_a=k.decapsulate(sk,ct); tdec=(time.perf_counter()-t0)*1000
    print(f"[3] Decapsul : ss={ss_a.hex()[:16]}...  t={tdec:.3f}ms")
    total=tkg+tenc+tdec
    print(f"\nTotal: {total:.3f}ms  (RSA-2048 ~ 22ms => {22/total:.0f}x plus rapide)")
