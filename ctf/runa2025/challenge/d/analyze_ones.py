#!/usr/bin/env python3
"""
Find indices where oracle[i] = 1, which tells us about d's bit structure
"""

with open("challenge.txt", "r") as f:
    oracle_values = [int(line.strip()) for line in f]

shift = [ 5, 11, 18, 24, 30, 37, 43, 51, 57, 63, 70, 78, 84, 90, 98, 105, 112, 120, 125, 131, 137, 144, 150, 156,
161, 169, 176, 180, 187, 193, 201, 205, 212, 220, 228, 235, 239, 246, 252, 258, 265, 269, 277, 283, 290,
295, 301, 307, 311, 318, 326, 330, 337, 345, 353, 360, 365, 370, 377, 383, 389, 397, 405, 409, 413, 421,
429, 433, 441, 446, 454, 461, 468, 476, 483, 490, 497, 504, 510, 517, 524, 531, 538, 546, 551, 559, 562,
569, 577, 584, 590, 596, 599, 606, 609, 617, 624, 631, 638, 642, 648, 653, 658, 662, 670, 676, 681, 689,
693, 700, 708, 716, 723, 730, 738, 746, 753, 758, 763, 769, 778, 784, 790, 796, 804, 812, 819, 826, 831,
838, 844, 850, 858, 865, 869, 876, 883, 890, 897, 903, 910, 917, 925, 932, 939, 945, 950, 954, 959, 963,
969, 976, 983, 989, 993, 998, 1005, 1010, 1016, 1021 ]

print("[*] Indices where oracle[i] = 1:")
ones_indices = []
for i, val in enumerate(oracle_values):
    if val == 1:
        ones_indices.append(i)
        print(f"  Index {i:3d}: shift={shift[i]:4d}")

print(f"\n[+] Found {len(ones_indices)} indices with oracle = 1")

if ones_indices:
    first_one = ones_indices[0]
    last_one = ones_indices[-1]
    
    print(f"\n[*] First oracle=1 at index {first_one}, shift={shift[first_one]}")
    print(f"[*] Last oracle=1 at index {last_one}, shift={shift[last_one]}")
    
    print(f"\n[!] Interpretation:")
    print(f"[!] For i >= {first_one}: oracle[i] = c^(d & mask[i]) = 1")
    print(f"[!] Where mask[i] = bits [{shift[i]}, 1024)")
    print(f"[!] This means (d & bits[{shift[first_one]}, 1024)) = 0 (most likely)")
    print(f"[!] Therefore: d < 2^{shift[first_one]}")
    
    # Check where oracles become 1
    print(f"\n[*] Oracle values near transition:")
    for i in range(max(0, first_one - 3), min(len(oracle_values), first_one + 5)):
        print(f"  Index {i:3d}: shift={shift[i]:4d}, oracle={oracle_values[i]}")

print(f"\n[*] All oracle values that are 1:")
ones_count = sum(1 for v in oracle_values if v == 1)
print(f"  Total count: {ones_count}/160")
