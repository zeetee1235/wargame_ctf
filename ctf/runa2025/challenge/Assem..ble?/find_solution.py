#!/usr/bin/env python3
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
    
    return r14

def find_char_at_pos(pos, target_length):
    r13 = target_length & 0xff
    high_nibble = (pos >> 4) & 0xf
    table_idx = (high_nibble * 2) + 1
    low_nibble = pos & 0xf
    table_byte = tables[table_idx][low_nibble]
    
    r8_after_xor_add = table_byte
    r8_after_xor = (r8_after_xor_add - r13) & 0xff
    target_shuffle = r8_after_xor ^ r13
    
    for c in range(256):
        if bit_shuffle(c) == target_shuffle:
            return c
    return None

# Try different lengths to find the correct one
print("Trying different string lengths...")
for test_len in range(1, 64):
    result = []
    for pos in range(test_len):
        char = find_char_at_pos(pos, test_len)
        if char is not None:
            result.append(char)
        else:
            break
    
    if len(result) == test_len:
        result_bytes = bytes(result)
        # Check if it passes
        check = check_string(result_bytes)
        if check == 0:
            print(f"\n{'='*70}")
            print(f"FOUND SOLUTION! Length: {test_len}")
            print(f"{'='*70}")
            print(f"Hex: {result_bytes.hex()}")
            print(f"String: {result_bytes}")
            
            # Try to decode
            try:
                decoded = result_bytes.decode('ascii')
                print(f"ASCII: {decoded}")
            except:
                try:
                    decoded = result_bytes.decode('latin-1')
                    print(f"Latin-1: {decoded}")
                except:
                    print("Cannot decode as text")
            
            # Test it
            print(f"\nVerification: r14 = 0x{check:02x}")
            break
        elif all(32 <= c < 127 for c in result_bytes):
            # Printable ASCII
            print(f"Length {test_len:2d}: {result_bytes.decode('ascii')[:40]} (r14=0x{check:02x})")
        else:
            # Contains non-printable
            printable = ''.join(chr(c) if 32 <= c < 127 else '?' for c in result_bytes)
            print(f"Length {test_len:2d}: {printable[:40]} (r14=0x{check:02x})")
