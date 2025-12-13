#!/usr/bin/env python3
"""
Try Wiener attack: if d < n^0.25, we can recover it via continued fractions
"""

from math import gcd
from fractions import Fraction

n = 135167602461771521046398733682044487427151190421984842702500364108379554466122969256074390858680451518196618847623869798746472330017140411187430178145882297680332311503967440717783516743306270572112741236778386958796974257309551133263576375229487188188891779118341977094309342252909562493989354685543631839923

c = 79895995276895734470794266855522790970954321405659758332884445891083719342568320178937336413936683188341972215794445514516572834930487327548794166247078140550838657442054349291626802103425586065455759111886276588148975868238628082856438829870613298404515633393126627015346958400380138077130619435917836339299

# Actually, we need e, not c
# But c is given, not e

# Wiener attack requires e and n, where e is the PUBLIC EXPONENT
# We have c which is ciphertext and we don't have e

# So Wiener attack won't work here directly

# Let's think differently: Can we use information from oracle values?

print("[*] Wiener attack requires e (public exponent)")
print("[!] We only have c (ciphertext), not e")
print("[!] Wiener attack not applicable")

# Alternative: Small exponent/small d Coppersmith attack?
# But Coppersmith requires lattice reduction for d < n^0.292

print("\n[*] Checking if d might be small...")
print(f"[*] n^0.25 ≈ 10^{0.25 * 308}")  # Very rough estimate
print(f"[*] n^0.29 ≈ 10^{0.29 * 308}")

# Without more information, this is very difficult

print("\n[!] Need different approach or additional information")
