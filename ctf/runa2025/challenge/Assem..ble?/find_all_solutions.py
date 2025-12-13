#!/usr/bin/env python3
"""
다양한 길이에서 정답 문자열을 모두 찾아보기
"""

import struct

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
        r14 |= r8
    
    return r14 == 0

def find_char_at_pos(pos, target_length):
    r13 = target_length & 0xff
    high_nibble = (pos >> 4) & 0xf
    table_idx = (high_nibble * 2) + 1
    low_nibble = pos & 0xf
    table_byte = tables[table_idx][low_nibble]
    
    r8_after_xor_add = table_byte
    r8_after_xor = (r8_after_xor_add - r13) & 0xff
    target_shuffle = r8_after_xor ^ r13
    
    # Return ALL characters that match
    matches = []
    for c in range(256):
        if bit_shuffle(c) == target_shuffle:
            matches.append(c)
    return matches

print("="*70)
print("모든 가능한 길이에서 정답 찾기")
print("="*70)

solutions = []

for test_len in range(1, 65):
    result = []
    all_possible = [[]]  # Start with empty
    
    for pos in range(test_len):
        matches = find_char_at_pos(pos, test_len)
        if not matches:
            break
        
        # For now, just take the first match
        result.append(matches[0])
    
    if len(result) == test_len:
        result_bytes = bytes(result)
        if check_string(result_bytes):
            solutions.append((test_len, result_bytes))
            
            # Check if printable
            is_printable = all(32 <= c < 127 for c in result_bytes)
            
            print(f"\n길이 {test_len:2d}: ", end='')
            if is_printable:
                print(f"{result_bytes.decode('ascii')}")
            else:
                printable = ''.join(chr(c) if 32 <= c < 127 else f'\\x{c:02x}' for c in result_bytes)
                print(f"{printable}")
            
            # Check if it looks like a flag
            if b'runa' in result_bytes or b'flag' in result_bytes or b'{' in result_bytes:
                print(f"    >>> POSSIBLE FLAG! <<<")

print("\n" + "="*70)
print(f"총 {len(solutions)}개의 솔루션 발견")
print("="*70)

# 특히 긴 솔루션이 플래그일 가능성이 높음
if solutions:
    longest = max(solutions, key=lambda x: x[0])
    print(f"\n가장 긴 솔루션 (길이 {longest[0]}):")
    print(f"  Hex: {longest[1].hex()}")
    print(f"  Raw: {longest[1]}")
    
    try:
        decoded = longest[1].decode('ascii')
        print(f"  ASCII: {decoded}")
    except:
        pass
