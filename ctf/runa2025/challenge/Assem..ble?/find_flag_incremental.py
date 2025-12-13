#!/usr/bin/env python3
"""
길이 10부터 시작해서 한 글자씩 추가하며 플래그 찾기
"""

import struct
import string

# Read binary data
with open('prob', 'rb') as f:
    binary = f.read()

# Extract tables
pointers = []
for i in range(16):
    offset = 0x2114 + i * 8
    ptr = struct.unpack('<Q', binary[offset:offset+8])[0]
    pointers.append(ptr)

tables = []
for ptr in pointers:
    table_offset = ptr - 0x400000
    table_data = binary[table_offset:table_offset+16]
    tables.append(table_data)

def bit_shuffle(val):
    r8 = 0
    if val & 0x01: r8 |= 0x20
    if val & 0x02: r8 |= 0x40
    if val & 0x04: r8 |= 0x80
    if val & 0x08: r8 |= 0x01
    if val & 0x10: r8 |= 0x02
    if val & 0x20: r8 |= 0x04
    if val & 0x40: r8 |= 0x08
    if val & 0x80: r8 |= 0x10
    return r8

def check_string(s):
    r13 = len(s) & 0xff
    r14 = 0
    
    for r12, char in enumerate(s):
        r8 = bit_shuffle(char)
        r8 = (r8 ^ r13) & 0xff
        r8 = (r8 + r13) & 0xff
        
        high_nibble = (r12 >> 4) & 0xf
        table_idx = (high_nibble * 2) + 1
        low_nibble = r12 & 0xf
        
        table_byte = tables[table_idx][low_nibble]
        r8 ^= table_byte
        r14 = (r14 + r8) & 0xff
    
    return r14 == 0

print("=" * 70)
print("길이별로 runa2025{로 시작하는 플래그 찾기")
print("=" * 70)
print()

# 알려진 솔루션들
known = {
    1: b'b',
    2: b'ru',
    10: b'runa2025{a',
    42: b'pula0605{a142ace93d9255`ea57c4cc4`7e`a024d',
}

# 길이 10부터 각 길이에서 printable한 답 찾기
charset = (string.ascii_letters + string.digits + '_{}-./!@#$%^&*()').encode()

for length in range(10, 65):
    print(f"\n길이 {length}:", end=' ')
    
    if length in known:
        sol = known[length]
        print(f"(이미 알려진) {sol}")
        continue
    
    # runa2025{로 시작해야 함
    if length < 9:
        continue
        
    prefix = b'runa2025{'
    if length < len(prefix):
        prefix = b'runa2025{'[:length]
    
    remaining = length - len(prefix)
    
    # Try all combinations of remaining characters
    from itertools import product
    
    max_tries = 1000000
    tried = 0
    found = False
    
    for combo in product(charset, repeat=remaining):
        if tried >= max_tries:
            break
        tried += 1
        
        candidate = prefix + bytes(combo)
        if len(candidate) != length:
            continue
            
        if check_string(candidate):
            # Check if printable
            try:
                decoded = candidate.decode('ascii')
                print(f"발견! {candidate}")
                found = True
                break
            except:
                pass
    
    if not found:
        print(f"({tried:,}번 시도, 못 찾음)")
