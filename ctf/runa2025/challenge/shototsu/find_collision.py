#!/usr/bin/env python3
"""
shototsu - collision finder
"""

import sys
sys.path.insert(0, '/home/dev/wargame_ctf/runa_ctf/shototsu')
from prob import encrypt

# 알려진 collision
t1_hex = "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9"
t2_hex = "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9"

t1 = bytes.fromhex(t1_hex)
t2 = bytes.fromhex(t2_hex)

print("[*] shototsu - Collision Finder")
print(f"[+] Known collision verified: {encrypt(t1) == encrypt(t2)}")

# 다른 위치에서 비슷한 bit pattern 변화를 만들기
def create_variant(data, pos1_delta, pos2_delta, pos3_delta):
    """
    Create a variant by copying the same deltas to different positions
    """
    result = bytearray(data)
    # Change positions with same delta
    result[0] ^= pos1_delta
    result[4] ^= pos2_delta
    result[16] ^= pos3_delta
    return bytes(result)

print("\n[*] Trying to find new collision...")

# Simple bit flip strategy
found = False
count = 0

# 전체 탐색은 너무 크므로, 몇 가지 전략만 시도:

# 1. Same byte changes at different positions
print("[+] Strategy 1: Copying byte deltas to different positions")

for offset in range(0, 64, 4):
    # Changes at positions relative to offset
    m1 = bytearray(t1)
    m2 = bytearray(t2)
    
    # Apply same changes at different positions
    if offset + 7 < 64 and offset + 11 < 64 and offset + 50 < 64:
        m1[offset + 0] = t1[7]
        m1[offset + 4] = t1[11]
        
        m2[offset + 0] = t2[7]
        m2[offset + 4] = t2[11]
        
        m1 = bytes(m1)
        m2 = bytes(m2)
        
        if m1 != m2 and m1 != t1 and m1 != t2 and m2 != t1 and m2 != t2:
            if encrypt(m1) == encrypt(m2):
                print(f"[!] Found collision at offset {offset}!")
                print(f"    m1: {m1.hex()}")
                print(f"    m2: {m2.hex()}")
                found = True
                break

# 2. Reverse engineering: modify messages slightly
print("\n[+] Strategy 2: Small modifications")

test_messages = [
    t1[::-1],  # Reversed
    bytes(reversed(bytearray(t1))),  # Also reversed
    bytes(b ^ 0xFF for b in t1),  # Inverted
]

for i, msg in enumerate(test_messages):
    if msg != t1 and msg != t2:
        try:
            h_msg = encrypt(msg)
            if h_msg == encrypt(t1):
                print(f"[!] Found collision with test {i}!")
                print(f"    msg: {msg.hex()}")
                found = True
                break
        except:
            pass

if not found:
    print("[-] No easy collision found, need more sophisticated approach")
    print("\n[*] Hint: The diff pattern might repeat at different block boundaries")
    
    # 더 정교한 공격
    # MD4 attack 이용: differential path 따라가기
    print("\n[+] Trying differential attack...")
    
    # Known differential: bit position changes
    deltas = [
        (0x80, 0, 0),      # Position 7: 0xd6 -> 0x56
        (0, 0x90, 0),      # Position 11: 0x29 -> 0xb9
        (0, 0, 0x01),      # Position 50: 0xdc -> 0xdd
    ]
    
    for d1, d2, d3 in deltas:
        for p1 in range(0, 64, 4):
            for p2 in range(0, 64, 4):
                for p3 in range(0, 64, 4):
                    if p1 == p2 or p2 == p3 or p1 == p3:
                        continue
                    if p1 + 1 >= 64 or p2 + 1 >= 64 or p3 + 1 >= 64:
                        continue
                    
                    m1 = bytearray(t1)
                    m2 = bytearray(t1)
                    
                    m2[p1] ^= d1
                    m2[p2] ^= d2
                    m2[p3] ^= d3
                    
                    m1, m2 = bytes(m1), bytes(m2)
                    
                    if m1 != m2 and m1 != t2 and m2 != t2:
                        if encrypt(m1) == encrypt(m2):
                            print(f"[!] COLLISION FOUND!")
                            print(f"    m1: {m1.hex()}")
                            print(f"    m2: {m2.hex()}")
                            found = True
                            break
                
                if found:
                    break
            if found:
                break

