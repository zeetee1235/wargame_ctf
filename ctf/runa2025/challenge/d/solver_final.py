#!/usr/bin/env python3
"""
Recover d using knowledge that d < 2^156

Strategy:
1. Oracle[23+] = 1 tells us d & bits[156, 1024) = 0
2. So d is fully contained in bits [0, 156)
3. Use oracle ratios to recover bits [5, 156)
4. Bits [0, 5) can be determined from oracle[0]
"""

from Crypto.Util.number import *

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

# Load oracle values
with open("challenge.txt", "r") as f:
    oracle = [int(line.strip()) for line in f]

print("[*] Problem constraint: d < 2^156")
print("[*] Attempting to recover 156-bit d...")

# Key insight: For i >= 23, oracle[i] = 1 means (d & bits[156, 1024)) = 0
# So all d bits are in range [5, 156) (since shift[0] = 5)

# Use oracle ratios
d_bits = {}

# Try all pairs (i, i+1) where 0 <= i < 23
for i in range(23):
    s_i = shift[i]
    s_next = shift[i + 1]
    
    bit_range = s_next - s_i
    
    print(f"\n[*] Range [{s_i}:{s_next}), {bit_range} bits")
    print(f"    oracle[{i}] = {oracle[i]}")
    print(f"    oracle[{i+1}] = {oracle[i+1]}")
    
    # Compute ratio
    try:
        oracle_next_inv = pow(oracle[i+1], -1, n)
        ratio = (oracle[i] * oracle_next_inv) % n
        print(f"    ratio = {ratio}")
    except:
        print(f"    ERROR: Could not invert oracle[{i+1}]")
        continue
    
    # Brute force small ranges
    if bit_range <= 20:
        print(f"    Brute forcing 2^{bit_range} = {1 << bit_range} attempts...")
        found = False
        for guess in range(1 << bit_range):
            if pow(c, guess, n) == ratio:
                print(f"    [+] FOUND: bits [{s_i}:{s_next}] = {bin(guess)[2:].zfill(bit_range)}")
                for j in range(bit_range):
                    bit_pos = s_i + j
                    d_bits[bit_pos] = (guess >> j) & 1
                found = True
                break
        
        if not found:
            print(f"    [-] No match in brute force")
    else:
        print(f"    [!] Range too large ({bit_range} > 20), skipping brute force")

print(f"\n[*] Recovered {len(d_bits)} bits")

# Reconstruct d
d_candidate = 0
for bit_pos, bit_val in d_bits.items():
    if bit_val:
        d_candidate |= (1 << bit_pos)

print(f"\n[*] d_candidate = {hex(d_candidate)}")
print(f"[*] d_candidate bit length: {d_candidate.bit_length()}")

# Try to decode
try:
    d_bytes = long_to_bytes(d_candidate)
    print(f"\n[+] As string: {d_bytes}")
    
    if b"runa" in d_bytes:
        print("[+] FLAG FOUND!")
except:
    pass

# Verify first few oracles
if len(d_bits) > 0:
    print(f"\n[*] Verification:")
    for test_i in range(min(5, 23)):
        mask_i = ((1 << (1024 - shift[test_i])) - 1) << shift[test_i]
        fault_i = d_candidate & mask_i
        computed = pow(c, fault_i, n)
        actual = oracle[test_i]
        
        match = "✓" if computed == actual else "✗"
        print(f"    oracle[{test_i}]: computed={computed % (10**30)}, actual={actual % (10**30)} {match}")
