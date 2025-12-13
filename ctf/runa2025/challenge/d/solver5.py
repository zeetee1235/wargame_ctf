#!/usr/bin/env python3
"""
LSB Oracle Attack using ratios between oracles
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
print(f"[*] c = {c}")
print(f"[*] n = {n}")

# Key insight:
# oracle[i] = c^(d & mask[i]) mod n
# where mask[i] has bits [shift[i], 1023] set
#
# ratio[i] = oracle[i] / oracle[i+1] = c^((d & mask[i]) - (d & mask[i+1])) mod n
#
# The difference (d & mask[i]) - (d & mask[i+1]) depends on
# bits in range [shift[i], shift[i+1])

print("\n[*] Computing ratios between consecutive oracles...")

# For consecutive shifts s_i < s_{i+1}:
# mask[i] keeps bits [s_i, ..., 1023]
# mask[i+1] keeps bits [s_{i+1}, ..., 1023]
# The difference is in bits [s_i, ..., s_{i+1}-1]

# oracle[i] / oracle[i+1] = c^(d & ((mask[i] XOR mask[i+1])))

# Let's check how many bits differ
diffs = []
for i in range(len(shift) - 1):
    s1 = shift[i]
    s2 = shift[i + 1]
    nbits_differ = s2 - s1
    diffs.append(nbits_differ)
    print(f"  oracle[{i}] vs [{i+1}]: shifts {s1} vs {s2}, {nbits_differ} bits differ")

# Now, the key: d[s_i:s_{i+1}] determines how much each oracle pair differs
# oracle[i] / oracle[i+1] = c^(d[s_i:s_{i+1}])

# But d[s_i:s_{i+1}] is just some integer between 0 and 2^(s2-s1) - 1

# We can use Pohlig-Hellman if we can factor the exponent orders!
# But that requires knowing the order of c modulo n

# Alternative: use the fact that we have many constraints
# Try to find a pattern or use linear algebra

print("\n[*] Testing if we can deduce some bits...")

# For very small bit ranges, we might be able to brute force
# Try the ranges with smallest number of bits

min_bit_range_idx = diffs.index(min(diffs))
print(f"\n[*] Smallest bit range: oracle[{min_bit_range_idx}] to [{min_bit_range_idx+1}]")
print(f"    {diffs[min_bit_range_idx]} bits differ")

# Let's try to brute force this range
s1 = shift[min_bit_range_idx]
s2 = shift[min_bit_range_idx + 1]
nbits = s2 - s1

o1 = oracle[min_bit_range_idx]
o2 = oracle[min_bit_range_idx + 1]

ratio = (o1 * inverse(o2, n)) % n

print(f"\n[*] oracle[{min_bit_range_idx}] / oracle[{min_bit_range_idx+1}] ≡ {hex(ratio)} (mod n)")
print(f"[*] This should equal c^(d bits [{s1}, {s2})) (mod n)")

# Brute force the bits in this range
print(f"\n[*] Brute forcing {nbits} bits...")

max_val = 1 << nbits
found = False

for val in range(max_val):
    if pow(c, val, n) == ratio:
        print(f"[+] Found: d[{s1}:{s2}] = {val} ({bin(val)[2:].zfill(nbits)})")
        found = True
        break
    
    if val % 10000 == 0:
        print(f"  Tried {val}/{max_val}...")

if not found:
    print("[-] Not found in brute force")

print("\n[*] Note: This approach has limited scope due to discrete log hardness")
print("[*] A full solution would require factoring n or using lattice methods")
