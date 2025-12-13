#!/usr/bin/env python3
"""
LSB Oracle Attack on RSA
Recovering the secret key 'd' from faulty decryption oracles
"""

from Crypto.Util.number import long_to_bytes, bytes_to_long
import sys

# Given data
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

# Read fault data
with open("challenge.txt") as f:
    fault_d = [int(line.strip()) for line in f.readlines()]

print(f"[*] Loaded {len(fault_d)} faulty decryptions")
print(f"[*] Total bits: {TOTAL_BITS}")

# Extract bits from each oracle
# For each shift[i], we know d & mask where mask has top (1024 - shift[i]) bits set
recovered_bits = {}

for idx, s in enumerate(shift):
    oracle_result = fault_d[idx]
    
    # The mask for this oracle keeps bits from position s to 1023
    mask_bits = TOTAL_BITS - s
    
    # oracle_result = c^(d & mask) mod n
    # where mask = ((1 << mask_bits) - 1) << s
    
    # We need to verify which bits of d are set by checking
    # if c^(guess) mod n == oracle_result
    
    recovered_bits[s] = oracle_result
    print(f"[*] shift[{idx}] = {s}: Got c^(d & mask) where mask covers bits {s}-{TOTAL_BITS-1}")

print("\n[*] Recovering secret key 'd' using meet-in-the-middle attack...")

# Strategy: Use the oracles to narrow down possible values
# Each oracle tells us: c^(d & mask) mod n
# We can verify our guesses against these values

def verify_d_candidate(d_guess):
    """Verify if d_guess matches all oracle outputs"""
    for idx, s in enumerate(shift):
        mask = ((1 << (TOTAL_BITS - s)) - 1) << s
        masked_d = d_guess & mask
        expected = pow(c, masked_d, n)
        if expected != fault_d[idx]:
            return False
    return True

# Binary search / incremental reconstruction
print("\n[*] Attempting to reconstruct 'd' bit by bit...")

d = 0
# Start from the most significant bits
for bit_pos in range(TOTAL_BITS - 1, -1, -1):
    # Try setting this bit to 1
    d_try = d | (1 << bit_pos)
    
    # Check if this is still consistent with oracles that cover this bit
    is_valid = True
    for idx, s in enumerate(shift):
        if s <= bit_pos:  # This oracle covers this bit position
            mask = ((1 << (TOTAL_BITS - s)) - 1) << s
            masked_d = d_try & mask
            expected = pow(c, masked_d, n)
            if expected != fault_d[idx]:
                is_valid = False
                break
    
    if is_valid:
        d = d_try
        if bit_pos % 100 == 0:
            print(f"[+] Bit {bit_pos}: set to 1")
    else:
        print(f"[+] Bit {bit_pos}: set to 0")
    
    if bit_pos % 100 == 0:
        print(f"    Current d: {bin(d)[2:].zfill(TOTAL_BITS)[:50]}...")

print(f"\n[*] Recovered d: {d}")

# Try to convert to text
try:
    flag = long_to_bytes(d)
    if b'runa2025' in flag:
        print(f"\n[+] FLAG FOUND: {flag.decode('utf-8', errors='ignore')}")
    else:
        print(f"\n[*] Decoded d: {flag}")
except:
    print(f"\n[*] Could not decode as string")

# Verify against all oracles
print(f"\n[*] Verifying d against all oracles...")
errors = 0
for idx, s in enumerate(shift):
    mask = ((1 << (TOTAL_BITS - s)) - 1) << s
    masked_d = d & mask
    expected = pow(c, masked_d, n)
    if expected == fault_d[idx]:
        if idx % 20 == 0:
            print(f"[+] Oracle {idx}: OK")
    else:
        print(f"[-] Oracle {idx}: FAILED")
        errors += 1

if errors == 0:
    print(f"[+] All {len(shift)} oracles verified!")
else:
    print(f"[-] {errors} oracles failed")
