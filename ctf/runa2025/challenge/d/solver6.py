#!/usr/bin/env python3
"""
LSB Oracle Attack - Brute force small ranges
"""

from Crypto.Util.number import long_to_bytes, inverse
import sys

n = 135167602461771521046398733682044487427151190421984842702500364108379554466122969256074390858680451518196618847623869798746472330017140411187430178145882297680332311503967440717783516743306270572112741236778386958796974257309551133263576375229487188188891779118341977094309342252909562493989354685543631839923
c = 79895995276895734470794266855522790970954321405659758332884445891083719342568320178937336413936683188341972215794445514516572834930487327548794166247078140550838657442054349291626802103425586065455759111886276588148975868238628082856438829870613298404515633393126627015346958400380138077130619435917836339923

shift = [5, 11, 18, 24, 30, 37, 43, 51, 57, 63, 70, 78, 84, 90, 98, 105, 112, 120, 125, 131, 137, 144, 150, 156,
161, 169, 176, 180, 187, 193, 201, 205, 212, 220, 228, 235, 239, 246, 252, 258, 265, 269, 277, 283, 290,
295, 301, 307, 311, 318, 326, 330, 337, 345, 353, 360, 365, 370, 377, 383, 389, 397, 405, 409, 413, 421,
429, 433, 441, 446, 454, 461, 468, 476, 483, 490, 497, 504, 510, 517, 524, 531, 538, 546, 551, 559, 562,
569, 577, 584, 590, 596, 599, 606, 609, 617, 624, 631, 638, 642, 648, 653, 658, 662, 670, 676, 681, 689,
693, 700, 708, 716, 723, 730, 738, 746, 753, 758, 763, 769, 778, 784, 790, 796, 804, 812, 819, 826, 831,
838, 844, 850, 858, 865, 869, 876, 883, 890, 897, 903, 910, 917, 925, 932, 939, 945, 950, 954, 959, 963,
969, 976, 983, 989, 993, 998, 1005, 1010, 1016, 1021]

TOTAL_BITS = 1024

with open("challenge.txt") as f:
    oracle = [int(line.strip()) for line in f.readlines()]

print(f"[*] Loaded {len(oracle)} oracles")

# Brute force bit ranges between consecutive shifts
print("\n[*] Brute forcing bit ranges...")

d_bits = {}  # Maps bit ranges to values

for idx in range(len(shift) - 1):
    s1 = shift[idx]
    s2 = shift[idx + 1]
    nbits = s2 - s1
    
    o1 = oracle[idx]
    o2 = oracle[idx + 1]
    
    ratio = (o1 * inverse(o2, n)) % n
    
    # Brute force
    max_val = 1 << nbits
    
    # Only brute force small ranges
    if nbits > 12:
        print(f"[-] Range [{s1}, {s2}): {nbits} bits (too large to brute force)")
        continue
    
    found_val = None
    for val in range(max_val):
        if pow(c, val, n) == ratio:
            found_val = val
            break
    
    if found_val is not None:
        d_bits[(s1, s2)] = found_val
        print(f"[+] Range [{s1}, {s2}): {nbits} bits = {found_val} ({bin(found_val)[2:].zfill(nbits)})")
    else:
        print(f"[-] Range [{s1}, {s2}): {nbits} bits (no match found)")

# Reconstruct d from the bit ranges
print(f"\n[*] Reconstructing d from {len(d_bits)} bit ranges...")

d_reconstructed = 0

for (s1, s2), val in sorted(d_bits.items()):
    # Place val at position [s1, s2)
    d_reconstructed |= (val << s1)

print(f"\n[*] Reconstructed d (partial): {hex(d_reconstructed)}")

# Try to decode
try:
    result = long_to_bytes(d_reconstructed)
    print(f"\n[+] Decoded d: {result}")
    if b'runa2025' in result:
        print(f"[+] FLAG FOUND: {result.decode('utf-8', errors='ignore')}")
except Exception as e:
    print(f"\n[-] Could not decode: {e}")

# Verify the known ranges
print(f"\n[*] Verifying reconstructed d against all oracles...")
errors = 0
correct = 0
for idx, s in enumerate(shift):
    mask = ((1 << (1024 - s)) - 1) << s
    m = d_reconstructed & mask
    expected = pow(c, m, n)
    if expected == oracle[idx]:
        correct += 1
    else:
        errors += 1

print(f"[*] Oracle matching: {correct}/{len(oracle)}")
