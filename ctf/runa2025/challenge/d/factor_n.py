#!/usr/bin/env python3
"""
Attempt to factor n using multiple methods and apply Pohlig-Hellman if successful
"""

from Crypto.Util.number import *
from math import gcd, isqrt
import sys

n = 135167602461771521046398733682044487427151190421984842702500364108379554466122969256074390858680451518196618847623869798746472330017140411187430178145882297680332311503967440717783516743306270572112741236778386958796974257309551133263576375229487188188891779118341977094309342252909562493989354685543631839923

print(f"[*] N has {n.bit_length()} bits")

# Try small factors
print("[*] Checking small factors...")
for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
    if n % p == 0:
        print(f"[+] Found factor: {p}")
        q = n // p
        print(f"[+] n = {p} * {q}")
        sys.exit(0)

# Try Fermat's method for small difference
print("[*] Trying Fermat's method...")
def fermat(n, max_iter=10000):
    x = isqrt(n) + 1
    for i in range(max_iter):
        y2 = x*x - n
        y = isqrt(y2)
        if y*y == y2:
            return (x+y, x-y)
        x += 1
    return None

result = fermat(n)
if result:
    p, q = result
    print(f"[+] Fermat found factors: {p}, {q}")
    sys.exit(0)
else:
    print("[-] Fermat's method didn't find factors within iterations")

# Try Pollard's rho
print("[*] Trying Pollard's rho...")
def pollard_rho(n, max_iter=100000):
    if n % 2 == 0:
        return 2
    
    x = 2
    y = 2
    d = 1
    
    f = lambda x: (x*x + 1) % n
    
    for _ in range(max_iter):
        x = f(x)
        y = f(f(y))
        d = gcd(abs(x - y), n)
        
        if d != 1:
            if d != n:
                return d
            else:
                return None
    return None

factor = pollard_rho(n)
if factor and factor != n:
    print(f"[+] Pollard's rho found factor: {factor}")
    q = n // factor
    print(f"[+] n = {factor} * {q}")
    sys.exit(0)
else:
    print("[-] Pollard's rho didn't find factors")

print("\n[!] Unable to factor n with these methods")
print("[!] n appears to be a product of two large primes (secure RSA)")
