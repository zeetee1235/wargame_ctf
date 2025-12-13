#!/usr/bin/env python3
import struct

# Read binary data
with open('prob', 'rb') as f:
    binary = f.read()

# Extract pointer table
pointers = []
for i in range(16):
    offset = 0x2114 + i * 8
    ptr = struct.unpack('<Q', binary[offset:offset+8])[0]
    pointers.append(ptr)
    print(f"Pointer[{i:2d}]: 0x{ptr:016x}")

# Extract lookup tables
tables = []
for ptr in pointers:
    table_offset = ptr - 0x400000  # ELF load address
    table_data = binary[table_offset:table_offset+16]
    tables.append(table_data)
    print(f"Table at 0x{ptr:x}: {table_data.hex()}")

print("\n" + "="*70)

def bit_shuffle(val):
    """Simulates the bit shuffle at 0x401074"""
    r8 = 0
    if val & 0x01: r8 |= 0x20  # bit 0 -> bit 5
    if val & 0x02: r8 |= 0x40  # bit 1 -> bit 6
    if val & 0x04: r8 |= 0x80  # bit 2 -> bit 7
    if val & 0x08: r8 |= 0x01  # bit 3 -> bit 0
    if val & 0x10: r8 |= 0x02  # bit 4 -> bit 1
    if val & 0x20: r8 |= 0x04  # bit 5 -> bit 2
    if val & 0x40: r8 |= 0x08  # bit 6 -> bit 3
    if val & 0x80: r8 |= 0x10  # bit 7 -> bit 4
    return r8

def check_string(s):
    """Check if string produces r14=0"""
    r13 = len(s) & 0xff
    r14 = 0
    
    for r12, char in enumerate(s):
        # Bit shuffle
        r8 = bit_shuffle(char)
        
        # XOR and ADD with length
        r8 = (r8 ^ r13) & 0xff
        r8 = (r8 + r13) & 0xff
        
        # Table lookup
        # Code: mov rax, r12; shr rax, 4; lea rax, [rax+rax*1+0x1]
        # Then: mov r10, [r11+rax*8]
        high_nibble = (r12 >> 4) & 0xf
        table_idx = (high_nibble * 2) + 1
        low_nibble = r12 & 0xf
        
        table_byte = tables[table_idx][low_nibble]
        
        # XOR with table value
        r8 ^= table_byte
        
        # OR into r14
        r14 |= r8
    
    return r14

# Test some inputs
test_inputs = [
    b"test",
    b"hello",
    b"flag",
    b"AAAA",
    b"runa2025"
]

print("\nTesting various inputs:")
for test in test_inputs:
    result = check_string(test)
    print(f"  {test.decode():20s} -> r14 = 0x{result:02x} {'✓ CORRECT!' if result == 0 else ''}")

# Try to brute force or reverse engineer the correct input
print("\n" + "="*70)
print("Analyzing first few characters...")
print("="*70)

# For each position, what value makes r8=0 after all operations?
def find_char_at_pos(pos, target_length):
    """Find character that makes r8=0 at given position"""
    r13 = target_length & 0xff
    high_nibble = (pos >> 4) & 0xf
    table_idx = (high_nibble * 2) + 1
    low_nibble = pos & 0xf
    table_byte = tables[table_idx][low_nibble]
    
    print(f"\nPosition {pos}:")
    print(f"  Length: {target_length}, r13: {r13}")
    print(f"  Table[{table_idx}][{low_nibble}] = 0x{table_byte:02x}")
    
    # We need: shuffle(char) XOR r13 + r13 XOR table_byte = 0
    # So: shuffle(char) = table_byte XOR r13 - r13
    target_after_xor_add = table_byte
    # Reverse: r8_after_xor = target - r13
    r8_after_xor = (target_after_xor_add - r13) & 0xff
    # Then: shuffle(char) = r8_after_xor XOR r13
    target_shuffle = r8_after_xor ^ r13
    
    print(f"  Target shuffle value: 0x{target_shuffle:02x}")
    
    # Find which character produces this shuffle
    for c in range(256):
        if bit_shuffle(c) == target_shuffle:
            print(f"  Character: 0x{c:02x} ('{chr(c) if 32<=c<127 else '?'}')")
            return c
    
    print(f"  No character found!")
    return None

# Try different lengths
for test_len in [4, 8, 16, 32]:
    print(f"\n{'='*70}")
    print(f"Trying length {test_len}:")
    print(f"{'='*70}")
    
    result = []
    for pos in range(min(test_len, 8)):  # Test first 8 chars
        char = find_char_at_pos(pos, test_len)
        if char is not None:
            result.append(char)
        else:
            break
    
    if len(result) == min(test_len, 8):
        result_bytes = bytes(result)
        print(f"\nPartial result: {result_bytes}")
        print(f"As string: {result_bytes.decode('latin-1')}")
