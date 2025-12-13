#!/usr/bin/env python3
"""
Exact verification of what challenge.txt contains
Try multiple interpretations
"""

from Crypto.Util.number import *

# Load oracle values from challenge.txt
with open("challenge.txt", "r") as f:
    oracle_values = [int(line.strip()) for line in f]

n = 135167602461771521046398733682044487427151190421984842702500364108379554466122969256074390858680451518196618847623869798746472330017140411187430178145882297680332311503967440717783516743306270572112741236778386958796974257309551133263576375229487188188891779118341977094309342252909562493989354685543631839923

c = 79895995276895734470794266855522790970954321405659758332884445891083719342568320178937336413936683188341972215794445514516572834930487327548794166247078140550838657442054349291626802103425586065455759111886276588148975868238628082856438829870613298404515633393126627015346958400380138077130619435917836339299

shift = [ 5, 11, 18, 24, 30, 37, 43, 51, 57, 63, 70, 78, 84, 90, 98, 105, 112, 120, 125, 131, 137, 144, 150, 156,
161, 169, 176, 180, 187, 193, 201, 205, 212, 220, 228, 235, 239, 246, 252, 258, 265, 269, 277, 283, 290,
295, 301, 307, 311, 318, 326, 330, 337, 345, 353, 360, 365, 370, 377, 383, 389, 397, 405, 409, 413, 421,
429, 433, 441, 446, 454, 461, 468, 476, 483, 490, 497, 504, 510, 517, 524, 531, 538, 546, 551, 559, 562,
569, 577, 584, 590, 596, 599, 606, 609, 617, 624, 631, 638, 642, 648, 653, 658, 662, 670, 676, 681, 689,
693, 700, 708, 716, 723, 730, 738, 746, 753, 758, 763, 769, 778, 784, 790, 796, 804, 812, 819, 826, 831,
838, 844, 850, 858, 865, 869, 876, 883, 890, 897, 903, 910, 917, 925, 932, 939, 945, 950, 954, 959, 963,
969, 976, 983, 989, 993, 998, 1005, 1010, 1016, 1021 ]

print("[*] Loaded challenge.txt")
print(f"[*] oracle[0] = {oracle_values[0]}")
print(f"[*] oracle[1] = {oracle_values[1]}")

# Theory 1: Check what c^0 mod n is
print(f"\n[*] Theory 1: Check c^0 mod n = {pow(c, 0, n)}")

# Theory 2: Try to see if these are actually c^(small values)
print(f"\n[*] Theory 2: Is oracle[0] = c^k for small k?")
for k in range(1, 20):
    if pow(c, k, n) == oracle_values[0]:
        print(f"    [+] Found: oracle[0] = c^{k} mod n")
        break

# Theory 3: Try inverse
print(f"\n[*] Theory 3: Try modular inverse relationships")
try:
    oracle_0_inv = pow(oracle_values[0], -1, n)
    print(f"    oracle[0]^-1 mod n exists")
    
    # Try division
    ratio = (oracle_values[1] * oracle_0_inv) % n
    print(f"    oracle[1] / oracle[0] mod n = {ratio}")
except Exception as e:
    print(f"    ERROR: {e}")

# Theory 4: Maybe they're small masked values?
print(f"\n[*] Theory 4: Maybe oracle values are small? (first 20 bits)")
print(f"    oracle[0] & ((1 << 20) - 1) = {oracle_values[0] & ((1 << 20) - 1)}")
print(f"    oracle[1] & ((1 << 20) - 1) = {oracle_values[1] & ((1 << 20) - 1)}")

# Theory 5: Are these actually d & mask values?
print(f"\n[*] Theory 5: If these were d & mask values...")
d_OR = 0
for val in oracle_values:
    d_OR |= val

print(f"    OR of all oracle values = {hex(d_OR)}")
try:
    d_OR_bytes = long_to_bytes(d_OR)
    print(f"    As string: {d_OR_bytes}")
except:
    pass

# Theory 6: Try to find any d value such that c^(d & mask) gives us oracle values
print(f"\n[*] Theory 6: What if we OR all oracle values as if they were d & mask?")
d_candidate = 0
for i, val in enumerate(oracle_values[:20]):
    d_candidate |= val

print(f"    d_candidate = {hex(d_candidate)}")

# Theory 7: Check smallest oracle values
print(f"\n[*] Theory 7: Statistics of oracle values")
oracle_sorted = sorted(oracle_values)
print(f"    Smallest 5: {oracle_sorted[:5]}")
print(f"    Largest 5: {oracle_sorted[-5:]}")
print(f"    Min bit length: {oracle_sorted[0].bit_length()}")
print(f"    Max bit length: {oracle_sorted[-1].bit_length()}")
