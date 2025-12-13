#!/usr/bin/env python3
"""
각 위치에서 모든 가능한 문자를 찾고, 
printable한 조합을 만들어 플래그를 찾기
"""

import struct
import itertools

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

def find_all_chars_at_pos(pos, target_length):
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

# Test specific lengths that seem promising
for test_len in [10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48]:
    print(f"\n{'='*70}")
    print(f"길이 {test_len} 분석:")
    print(f"{'='*70}")
    
    # Find all possible characters at each position
    all_possibilities = []
    for pos in range(test_len):
        chars = find_all_chars_at_pos(pos, test_len)
        if not chars:
            break
        all_possibilities.append(chars)
    
    if len(all_possibilities) != test_len:
        continue
    
    # Show what characters are possible
    print("Position | Possible chars")
    print("-" * 40)
    for i, chars in enumerate(all_possibilities[:min(test_len, 20)]):
        printable = [chr(c) if 32 <= c < 127 else f'\\x{c:02x}' for c in chars]
        print(f"  {i:2d}    | {', '.join(printable[:10])}")
    
    if test_len > 20:
        print(f"  ...   | (showing first 20 positions)")
    
    # Try to build printable string
    print("\nTrying to build printable string...")
    
    # Greedy approach: at each position, prefer printable ASCII
    result = []
    for i, chars in enumerate(all_possibilities):
        # Prefer lowercase, then uppercase, then digits, then other printable
        lowercase = [c for c in chars if 97 <= c <= 122]
        uppercase = [c for c in chars if 65 <= c <= 90]
        digits = [c for c in chars if 48 <= c <= 57]
        special = [c for c in chars if c in b'{}[]_-!@#$%^&*()']
        other_printable = [c for c in chars if 32 <= c < 127 and c not in lowercase and c not in uppercase and c not in digits and c not in special]
        
        if lowercase:
            result.append(lowercase[0])
        elif uppercase:
            result.append(uppercase[0])
        elif digits:
            result.append(digits[0])
        elif special:
            result.append(special[0])
        elif other_printable:
            result.append(other_printable[0])
        else:
            result.append(chars[0])
    
    result_bytes = bytes(result)
    if check_string(result_bytes):
        print(f"  Result: {result_bytes}")
        
        # Check if it looks like flag
        if b'runa2025{' in result_bytes and b'}' in result_bytes:
            start = result_bytes.find(b'runa2025{')
            end = result_bytes.find(b'}', start) + 1
            potential_flag = result_bytes[start:end]
            print(f"\n  🚩 POTENTIAL FLAG: {potential_flag}")
