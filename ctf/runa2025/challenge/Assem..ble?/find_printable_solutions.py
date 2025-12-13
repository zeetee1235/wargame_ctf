#!/usr/bin/env python3
"""
Printable ASCII만 있는 솔루션 찾기
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

def is_printable(s):
    """모든 문자가 printable ASCII인지 확인"""
    printable = set(string.printable.encode())
    return all(c in printable for c in s)

print("=" * 70)
print("Printable ASCII만 있는 솔루션 찾기")
print("=" * 70)
print()

printable_solutions = []

for length in range(1, 65):
    # Try all printable ASCII combinations (brute force for small lengths)
    if length <= 10:
        # Too many combinations, skip
        continue
    
    # For longer lengths, use the same search method
    from itertools import product
    
    # 특정 패턴으로만 시도 (runa2025{로 시작)
    prefix = b'runa2025{'
    if length < len(prefix):
        continue
        
    # prefix로 시작하는 문자열 생성
    remaining_len = length - len(prefix)
    
    # Try common flag characters
    charset = string.ascii_letters + string.digits + '_{}-'
    
    print(f"길이 {length}: 'runa2025{{' 로 시작하는 조합 테스트 중...", end='', flush=True)
    
    found = False
    tested = 0
    max_test = 100000  # 최대 테스트 수
    
    for combo in product(charset.encode(), repeat=remaining_len):
        if tested >= max_test:
            break
        tested += 1
        
        candidate = prefix + bytes(combo)
        if check_string(candidate):
            print(f" 발견!")
            print(f"  >>> {candidate.decode('ascii', errors='replace')}")
            printable_solutions.append((length, candidate))
            found = True
            break
    
    if not found:
        print(" (없음)")

print()
print("=" * 70)
print(f"총 {len(printable_solutions)}개의 printable 솔루션 발견")
print("=" * 70)
