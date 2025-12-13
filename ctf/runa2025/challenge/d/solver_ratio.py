#!/usr/bin/env python3
"""
Try to recover d using oracle ratio analysis and small brute force
Key idea: oracle[i] / oracle[i+1] = c^(bits in range [shift[i], shift[i+1]))
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
    oracle_values = [int(line.strip()) for line in f]

print(f"[*] Loaded {len(oracle_values)} oracle values")
print(f"[*] Analyzing bit ranges between consecutive shift values...")

# For each pair of consecutive shifts
d_bits = {}  # bit_position -> value (0 or 1)

for i in range(len(shift) - 1):
    s_i = shift[i]
    s_next = shift[i + 1]
    
    bit_range = s_next - s_i
    oracle_i = oracle_values[i]
    oracle_next = oracle_values[i + 1]
    
    if bit_range > 20:  # Skip large ranges (too slow to brute force)
        print(f"  Range [{s_i}, {s_next}): {bit_range} bits - too large, skipping")
        continue
    
    print(f"  Range [{s_i}, {s_next}): {bit_range} bits - attempting brute force...")
    
    # Compute ratio = oracle[i] / oracle[i+1]
    # This should equal c^(bits_in_range) mod n
    
    # But division modulo n is: oracle_i * oracle_next^(-1) mod n
    try:
        oracle_next_inv = pow(oracle_next, -1, n)
        ratio = (oracle_i * oracle_next_inv) % n
    except:
        print(f"    ERROR: Could not invert oracle[{i+1}] mod n")
        continue
    
    # Brute force: try all 2^bit_range values
    found = False
    for guess in range(1 << bit_range):
        # Compute c^guess mod n
        cguess = pow(c, guess, n)
        
        if cguess == ratio:
            print(f"    [+] FOUND: bits [{s_i}:{s_next}] = {bin(guess)[2:].zfill(bit_range)} ({guess})")
            
            # Store these bits
            for j in range(bit_range):
                bit_pos = s_i + j
                bit_val = (guess >> j) & 1
                if bit_pos in d_bits and d_bits[bit_pos] != bit_val:
                    print(f"    [!] WARNING: Contradiction at bit {bit_pos}")
                d_bits[bit_pos] = bit_val
            
            found = True
            break
    
    if not found:
        print(f"    [-] No match found in {1 << bit_range} attempts")

print(f"\n[*] Reconstructed {len(d_bits)} bit positions out of 1024")

# Try to reconstruct d
if len(d_bits) > 0:
    d_guess = 0
    for bit_pos, bit_val in d_bits.items():
        if bit_val:
            d_guess |= (1 << bit_pos)
    
    print(f"\n[*] Reconstructed d (partial): {hex(d_guess)}")
    
    # Try to decode as string
    try:
        d_bytes = long_to_bytes(d_guess)
        if b"runa" in d_bytes:
            print(f"[+] Contains 'runa': {d_bytes}")
    except:
        pass

print("\n[!] If few bits recovered, the problem may require different approach")
