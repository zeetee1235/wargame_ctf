#!/usr/bin/env python3
"""
Carefully reconstruct mask definitions and verify understanding
"""

TOTAL_BITS = 1024

# From prob.py
shift = [ 5, 11, 18, 24, 30, 37, 43, 51, 57, 63, 70, 78, 84, 90, 98, 105, 112, 120, 125, 131, 137, 144, 150, 156,
161, 169, 176, 180, 187, 193, 201, 205, 212, 220, 228, 235, 239, 246, 252, 258, 265, 269, 277, 283, 290,
295, 301, 307, 311, 318, 326, 330, 337, 345, 353, 360, 365, 370, 377, 383, 389, 397, 405, 409, 413, 421,
429, 433, 441, 446, 454, 461, 468, 476, 483, 490, 497, 504, 510, 517, 524, 531, 538, 546, 551, 559, 562,
569, 577, 584, 590, 596, 599, 606, 609, 617, 624, 631, 638, 642, 648, 653, 658, 662, 670, 676, 681, 689,
693, 700, 708, 716, 723, 730, 738, 746, 753, 758, 763, 769, 778, 784, 790, 796, 804, 812, 819, 826, 831,
838, 844, 850, 858, 865, 869, 876, 883, 890, 897, 903, 910, 917, 925, 932, 939, 945, 950, 954, 959, 963,
969, 976, 983, 989, 993, 998, 1005, 1010, 1016, 1021 ]

print("[*] Understanding mask generation from prob.py")
print("[*] mask = ((1 << (TOTAL_BITS - i)) - 1) << i")
print()

for idx in range(5):
    s = shift[idx]
    # mask = ((1 << (1024 - s)) - 1) << s
    # This is: (2^(1024-s) - 1) << s
    # = 2^(1024) - 2^s
    # In binary: 111...111000...000 where there are (1024-s) ones, then s zeros
    
    # So mask has bits [s, 1024) set to 1, bits [0, s) set to 0
    
    mask = ((1 << (TOTAL_BITS - s)) - 1) << s
    
    print(f"[Shift {idx}] shift={s}")
    print(f"  Bits set: [{s}, {TOTAL_BITS})")
    print(f"  Bits unset: [0, {s})")
    
    if idx < 4:
        s_next = shift[idx+1]
        print(f"  Next shift={s_next}")
        print(f"  Bit range between: [{s}, {s_next})")
        print()

print("\n[!] Key insight:")
print("[!] (d & mask[i]) & mask[i+1] = d & mask[i+1]")
print("[!] (d & mask[i]) & ~mask[i+1] = d & bits[shift[i], shift[i+1])")
print()
print("[!] Therefore:")
print("[!] (d & mask[i]) - (d & mask[i+1]) = d & bits[shift[i], shift[i+1])")
print("[!] (as integer subtraction, since (d & mask[i]) >= (d & mask[i+1]))")
print()
print("[*] So the ratio formula SHOULD work!")
print("[*] oracle[i] / oracle[i+1] = c^(d & bits[shift[i], shift[i+1])) mod n")
