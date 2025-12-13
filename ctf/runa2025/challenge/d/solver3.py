#!/usr/bin/env python3
"""
LSB Oracle Attack - Simple approach using oracle constraints
"""

from Crypto.Util.number import long_to_bytes
import sys

n = 135167602461771521046398733682044487427151190421984842702500364108379554466122969256074390858680451518196618847623869798746472330017140411187430178145882297680332311503967440717783516743306270572112741236778386958796974257309551133263576375229487188188891779118341977094309342252909562493989354685543631839923
c = 79895995276895734470794266855522790970954321405659758332884445891083719342568320178937336413936683188341972215794445514516572834930487327548794166247078140550838657442054349291626802103425586065455759111886276588148975868238628082856438829870613298404515633393126627015346958400380138077130619435917836339299

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

print(f"[*] {len(oracle)} oracles loaded")

# Key insight: For two consecutive shifts s_i and s_{i+1}
# oracle[i] = c^(d & mask_i) mod n  where mask_i has bits [s_i, 1023]
# oracle[i+1] = c^(d & mask_{i+1}) mod n where mask_{i+1} has bits [s_{i+1}, 1023]
# The difference is in bits [s_i, s_{i+1})

# Strategy: Build solution using relationships between consecutive oracles
#
# oracle[i+1] = c^(d & mask_{i+1})
# oracle[i] = c^(d & mask_i) = c^((d & mask_{i+1}) + (d & bits_in_range))
#
# So: oracle[i] = oracle[i+1] * c^(d & bits_in_[s_i, s_{i+1}))

print("\n[*] Computing relative masks...")

# For each pair of consecutive shifts, compute what bits differ
for i in range(min(5, len(shift) - 1)):
    s1 = shift[i]
    s2 = shift[i + 1]
    print(f"  oracle[{i}]: shift={s1} vs oracle[{i+1}]: shift={s2}")
    print(f"    Difference in bits: [{s1}, {s2})")
    print(f"    Number of bits: {s2 - s1}")

# Use logarithm relationship
# If c^a ≡ oracle[i] (mod n) and c^b ≡ oracle[i+1] (mod n)
# Then c^(a-b) ≡ oracle[i] * inv(oracle[i+1]) (mod n)

print("\n[*] Using discrete log relationships...")

# This is still complex. Let's use a different approach:
# We can compute d incrementally

# Since we have partial information, try to reconstruct d using
# the tightest constraint (highest shift value covers the most bits)

print("\n[*] Extracting high-order bits from highest-coverage oracles...")

# The last oracle (shift[159] = 1021) covers only top 3 bits
# c^(d >> 1021) ≡ oracle[159] (mod n)

#Actually, let's think differently:
# The mask for shift i is: ((1 << (1024 - shift[i])) - 1) << shift[i]
# This means bits [shift[i], 1023] are kept, bits [0, shift[i]-1] are cleared

# So the recovered value is: (d >> shift[i]) << shift[i]
# We get (d >> shift[i]) exactly!

print("\n[*] Direct bit extraction approach:")

# For shift[i], we get: d >> shift[i] in the exponent (after shifting back)

# Let's denote the number of bits kept as nbits[i] = 1024 - shift[i]
# We have: c^(d & mask[i]) ≡ oracle[i] (mod n)

# Try to find d by combining information from all oracles
# Use a constraint satisfaction approach

# Actually, the cleanest way: recover d bit by bit from MSB to LSB
# using the oracle that constrains each bit

print("\n[*] Building d incrementally (bit-by-bit from MSB)...")

d = 0
errors_per_bit = []

for bit in range(TOTAL_BITS - 1, -1, -1):
    # Try setting this bit to 1 or 0
    d_test_1 = d | (1 << bit)
    d_test_0 = d & ~(1 << bit)
    
    # Count errors for each choice
    errors_1 = 0
    errors_0 = 0
    
    for j, s in enumerate(shift):
        mask = ((1 << (1024 - s)) - 1) << s
        
        m1 = d_test_1 & mask
        m0 = d_test_0 & mask
        
        o = oracle[j]
        
        if pow(c, m1, n) != o:
            errors_1 += 1
        if pow(c, m0, n) != o:
            errors_0 += 1
    
    if errors_1 < errors_0:
        d = d_test_1
        choice = '1'
    elif errors_0 < errors_1:
        d = d_test_0
        choice = '0'
    else:
        # Equal errors, choose arbitrarily (or based on heuristic)
        if errors_1 == 0:
            d = d_test_1  # Both are perfect, prefer 1
            choice = '?'
        else:
            choice = '?'
    
    if bit % 64 == 0:
        print(f"[*] Bit {bit}: {choice} (errors: 1={errors_1}, 0={errors_0})")

print(f"\n[*] Final d: {hex(d)}")

# Verify
print(f"\n[*] Verification:")
errors_total = 0
for j, s in enumerate(shift):
    mask = ((1 << (1024 - s)) - 1) << s
    m = d & mask
    expected = pow(c, m, n)
    if expected != oracle[j]:
        errors_total += 1
        if errors_total <= 5:
            print(f"  [-] Oracle {j} failed")

print(f"[*] Total errors: {errors_total}/{len(shift)}")

# Decode
try:
    result = long_to_bytes(d)
    print(f"\n[+] Decoded d: {result}")
    if b'runa2025' in result:
        print(f"[+] FLAG FOUND: {result.decode('utf-8', errors='ignore')}")
except:
    pass

print(f"\n[*] d in binary (first 100 bits):")
print(bin(d)[2:].zfill(1024)[:100])
