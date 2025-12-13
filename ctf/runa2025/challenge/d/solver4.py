#!/usr/bin/env python3
"""
LSB Oracle Attack - Fast greedy approach
"""

from Crypto.Util.number import long_to_bytes

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

print(f"[*] Loaded {len(oracle)} oracles")

# Key observation: 
# oracle[i] = c^(d & mask[i]) mod n where mask[i] keeps bits [shift[i], 1023]
#
# For consecutive shifts s_i < s_{i+1}:
# oracle[i] corresponds to d with bits [0, s_i) cleared
# oracle[i+1] corresponds to d with bits [0, s_{i+1}) cleared
#
# The bits cleared in [s_i, s_{i+1}) affect the exponent differently

# More direct: For shift value s, the mask keeps the top (1024 - s) bits
# These are: bits [s, s+1, ..., 1023]

# So if we have enough oracles, we can determine each bit range

print("\n[*] Greedy bit reconstruction...")

d = 0
to_process = list(enumerate(shift))

def test_d(d_candidate, oracle_idx):
    s = shift[oracle_idx]
    mask = ((1 << (1024 - s)) - 1) << s
    m = d_candidate & mask
    return pow(c, m, n) == oracle[oracle_idx]

# Process bits from MSB to LSB
# For each bit position, determine if it should be 1 or 0

count = 0
for bit_pos in range(1023, -1, -1):
    # Find which oracle(s) constrain this bit
    constraining_oracles = [i for i, s in enumerate(shift) if s <= bit_pos]
    
    if not constraining_oracles:
        # No constraint, skip
        continue
    
    # Try setting the bit
    test_1 = d | (1 << bit_pos)
    test_0 = d  # bit is already 0
    
    # Check against a few constraining oracles
    matches_1 = sum(1 for i in constraining_oracles[:5] if pow(c, test_1 & (((1 << (1024 - shift[i])) - 1) << shift[i]), n) == oracle[i])
    matches_0 = sum(1 for i in constraining_oracles[:5] if pow(c, test_0 & (((1 << (1024 - shift[i])) - 1) << shift[i]), n) == oracle[i])
    
    if matches_1 >= matches_0:
        d = test_1
        choice = '1'
    else:
        choice = '0'
    
    count += 1
    if count % 100 == 0:
        print(f"[+] Processed {count} bits, current bit {bit_pos}: {choice}")

print(f"\n[*] Recovered d: {hex(d)}")

# Verify
print(f"\n[*] Verifying...")
errors = 0
for i, s in enumerate(shift):
    mask = ((1 << (1024 - s)) - 1) << s
    m = d & mask
    if pow(c, m, n) != oracle[i]:
        errors += 1

print(f"[*] Verification errors: {errors}/{len(oracle)}")

try:
    result = long_to_bytes(d)
    print(f"\n[+] d decoded: {result}")
except:
    print(f"\n[*] Could not decode as ASCII")
