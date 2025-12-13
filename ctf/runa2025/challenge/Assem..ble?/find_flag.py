#!/usr/bin/env python3
"""
runa2025{ 형식의 플래그를 찾기
"""

import struct

# Read binary
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
    
    matches = []
    for c in range(256):
        if bit_shuffle(c) == target_shuffle:
            matches.append(c)
    return matches

print("="*70)
print("runa2025{ 로 시작하는 플래그 찾기")
print("="*70)

# Find lengths where solution starts with "runa2025{"
target_prefix = b"runa2025{"

for test_len in range(len(target_prefix), 100):
    # Check if this length can produce the prefix
    matches_prefix = True
    for i, expected_char in enumerate(target_prefix):
        possible_chars = find_char_at_pos(i, test_len)
        if expected_char not in possible_chars:
            matches_prefix = False
            break
    
    if not matches_prefix:
        continue
    
    # Build the full string
    result = []
    for pos in range(test_len):
        chars = find_char_at_pos(pos, test_len)
        if not chars:
            break
        
        # If within prefix, use expected char
        if pos < len(target_prefix):
            if target_prefix[pos] in chars:
                result.append(target_prefix[pos])
            else:
                result.append(chars[0])
        else:
            # Try printable ASCII first
            printable = [c for c in chars if 32 <= c < 127]
            if printable:
                result.append(printable[0])
            else:
                result.append(chars[0])
    
    if len(result) == test_len:
        result_bytes = bytes(result)
        if check_string(result_bytes):
            # Check if it ends with }
            if b'}' in result_bytes:
                print(f"\n길이 {test_len}: {result_bytes}")
                
                # Try to make it fully printable
                # Maybe there are alternative chars at some positions
                print(f"  Hex: {result_bytes.hex()}")
                
                if result_bytes.startswith(b'runa2025{') and b'}' in result_bytes:
                    print(f"  >>> LIKELY THE FLAG! <<<")

print("\n" + "="*70)
print("모든 길이에서 'runa2025{' 로 시작하는 것들:")
print("="*70)

for test_len in range(9, 100):
    result = []
    for pos in range(test_len):
        chars = find_char_at_pos(pos, test_len)
        if not chars:
            break
        result.append(chars[0])
    
    if len(result) == test_len:
        result_bytes = bytes(result)
        if check_string(result_bytes):
            if result_bytes.startswith(b'runa2025{') or result_bytes.startswith(b'ruNA2025{') or result_bytes.startswith(b'ru'):
                print(f"길이 {test_len:2d}: {result_bytes[:50]}")
