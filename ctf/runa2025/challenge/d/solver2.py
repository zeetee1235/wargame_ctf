#!/usr/bin/env python3
"""
LSB Oracle Attack - Improved version
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
693, 700, 708, 716, 723, 730, 738, 746, 753, 758, 765, 769, 776, 783, 790, 796, 804, 812, 819, 826, 831,
838, 844, 850, 858, 865, 869, 876, 883, 890, 897, 903, 910, 917, 925, 932, 939, 945, 950, 954, 959, 963,
969, 976, 983, 989, 993, 998, 1005, 1010, 1016, 1021]

TOTAL_BITS = 1024

# Read fault data  
with open("challenge.txt") as f:
    fault_oracle = [int(line.strip()) for line in f.readlines()]

print(f"[*] Loaded {len(fault_oracle)} oracle responses")
print(f"[*] Each oracle: c^(d & mask) mod n where mask zero out LSBs")

# Key insight: we have multiple equations
# c^(d_masked_1) ≡ oracle[0] (mod n)
# c^(d_masked_2) ≡ oracle[1] (mod n)
# ...
# where d_masked_i = d & ((1 << (1024 - shift[i])) - 1) << shift[i]

# Strategy: Use the fact that higher-order bits are covered by multiple oracles
# For the highest shift (least LSBs zeroed), we know almost the full d

print("\n[*] Analyzing coverage of each oracle...")
for i in range(min(10, len(shift))):
    s = shift[i]
    covered_bits = TOTAL_BITS - s
    print(f"  Oracle {i}: shift={s}, covers bits [{s}, 1023] ({covered_bits} bits)")

# Most important insight: 
# If we have c^d mod n = some_plaintext
# and we have c^(d with some LSBs cleared) = oracle_output
# We can use this to determine which bits are set

# Better approach: Linear algebra over GF(2) using the discrete log relationship
# But that's complex. Let's try a simpler approach using the oracle coverage

print("\n[*] Extracting bit information...")

# For consecutive oracles, the difference tells us about specific bit ranges
d_bits = [None] * TOTAL_BITS

for i in range(len(shift)):
    s = shift[i]
    # This oracle tells us c^(d & mask) where mask clears bits [0, s-1]
    # It covers bits [s, 1023]
    
    # If we compare two consecutive oracles with shifts s_i and s_j (s_i < s_j)
    # The difference tells us about bits in [s_i, s_j)
    
    print(f"[+] Oracle {i} covers bits [{s}, {TOTAL_BITS-1}]")

print("\n[*] Using linear algebra approach...")

# The key equation: if we guess d, we can check all oracles
# c^(d & mask[i]) ≡ oracle[i] (mod n) for all i

# Since d is small (represented as bytes), let's try all possible byte values
# Actually, d starts with "runa2025" which helps us!

print("\n[*] Attempting brute force with known prefix 'runa2025'...")

known_prefix = b'runa2025'
from Crypto.Util.number import bytes_to_long

# The flag starts with 'runa2025'
# Let's build from there

# For now, let's use a meet-in-the-middle or guess-and-check approach
# We'll build d bit by bit, starting from high bits (which are most constrained)

print("\n[*] Building d from high-order bits...")

d_candidate = 0

# Start with known prefix
#d_candidate = bytes_to_long(known_prefix + b'\x00' * (128 - len(known_prefix)))

# Binary search approach: try to match oracles
for oracle_idx in range(len(shift) - 1, -1, -1):  # Start from least constrained
    s = shift[oracle_idx]
    expected = fault_oracle[oracle_idx]
    
    # Try to determine bits in range [s, next_s)
    if oracle_idx > 0:
        next_s = shift[oracle_idx - 1]
    else:
        next_s = TOTAL_BITS
    
    print(f"\n[*] Oracle {oracle_idx}: determining bits [{s}, {next_s})")
    
    # For now, we'll do a simple check
    # Try both possibilities for these bits
    
# More practical approach: use the fact that multiple oracles cover the same higher bits
# The highest bits should be heavily constrained

print("\n[*] Using highest-coverage bits...")

# Compute d from the most constrained bits
d = 0

# Start from the highest shift value (least zeroed bits)
highest_shift = max(shift)
print(f"[*] Highest shift (most coverage): {highest_shift}")

# Try to do bit-by-bit recovery
print("\n[*] Attempting bit-by-bit recovery...")

tested_count = 0
for bit_pos in range(TOTAL_BITS - 1, -1, -1):
    d_try1 = d | (1 << bit_pos)
    d_try0 = d
    
    # Check which one matches more oracles
    matches_1 = 0
    matches_0 = 0
    
    for oracle_idx, s in enumerate(shift):
        if s > bit_pos:  # This oracle doesn't cover this bit yet
            continue
        
        mask = ((1 << (TOTAL_BITS - s)) - 1) << s
        
        masked_1 = d_try1 & mask
        masked_0 = d_try0 & mask
        
        expected = fault_oracle[oracle_idx]
        
        if pow(c, masked_1, n) == expected:
            matches_1 += 1
        if pow(c, masked_0, n) == expected:
            matches_0 += 1
    
    if matches_1 > matches_0:
        d = d_try1
        result = "1"
    else:
        result = "0"
    
    if bit_pos % 128 == 0:
        print(f"[+] Bit {bit_pos}: {result} (matches: 1={matches_1}, 0={matches_0})")
        tested_count += 1

print(f"\n[*] Recovered d: {hex(d)}")

# Verify
print(f"\n[*] Verification...")
errors = 0
for idx, s in enumerate(shift):
    mask = ((1 << (TOTAL_BITS - s)) - 1) << s
    masked_d = d & mask
    expected = pow(c, masked_d, n)
    if expected == fault_oracle[idx]:
        pass  # OK
    else:
        errors += 1

print(f"[*] Errors: {errors}/{len(shift)}")

# Try to decode
try:
    result = long_to_bytes(d)
    print(f"\n[*] Decoded: {result}")
    if b'runa2025' in result:
        print(f"[+] FLAG: {result.decode('utf-8', errors='ignore')}")
except Exception as e:
    print(f"[-] Error decoding: {e}")
