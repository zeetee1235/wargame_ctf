#!/usr/bin/env python3

# Extract data from the binary
import struct

# Data section starting at 0x402000
data_section = bytes.fromhex("""
4eaed130 561656b6 6f3036d6 963070b0
3776d037 96b6b650 b030b6f6 70d67070
d650f6b0 50305696 d6d07050 96761730
569650d6 96b63096 90d63717 3090d050
70969696 1656f676 3716f690 90505017
b63070b0 b016d017 3696d637 56309637
1730f6d6 30f676b0 76d6d637 5690b0f6
d637d076 d0d630f6 305676b6 16b0d670
30d09030 70b096d6 56af2af4 5800bec0
7621c3cd 32163c6c c032d219 0e226360
0d74cbeb b50f3865 6a3e7c10 3b45bc2c
eb8ee25a a5e4e9cc 25dc0ea9 7db0749f
528fa996 b8264b8d 8c4b00b3 4ec4af7e
9d0cf62a 0b8e1b8a 0f7c7fb0 3f57535f
2da41f82 212c0485 604b8e25 84e79482
7a143593 3835e90f 0b6be219 53e88d3a
cc4c9ce7 481e3c3e b05ffd5d 25345d86
b31e033e
""".replace('\n', '').replace(' ', ''))

print(f"Data section length: {len(data_section)} bytes")
print(f"First 16 bytes: {data_section[:16].hex()}")

# Pointer table starts at 0x402114 (offset 0x114 in data section)
# Each entry is 8 bytes (64-bit pointer)
pointer_offset = 0x114
pointers = []

for i in range(16):  # There are 16 pointers (for nibbles 0-15)
    offset = pointer_offset + i * 8
    if offset + 8 <= len(data_section):
        ptr = struct.unpack('<Q', data_section[offset:offset+8])[0]
        pointers.append(ptr)
        print(f"Pointer[{i}]: 0x{ptr:016x}")

print("\nLookup tables:")
for i, ptr in enumerate(pointers):
    if ptr >= 0x402000 and ptr < 0x403000:
        table_offset = ptr - 0x402000
        print(f"\nTable {i} (at 0x{ptr:x}, offset 0x{table_offset:x}):")
        table_data = data_section[table_offset:table_offset+16]
        print(f"  Hex: {table_data.hex()}")
        print(f"  Bytes: {[f'0x{b:02x}' for b in table_data]}")

# The algorithm:
# For each character in input:
#   1. Bit shuffle (0x401074): rearrange bits
#   2. XOR with r13, ADD with r13 (0x4010b8)
#   3. Lookup in table and XOR (0x4010bf)
# Final r14 must be 0

print("\n" + "="*60)
print("Analyzing bit shuffle function (0x401074):")
print("="*60)

def bit_shuffle(byte_val):
    """
    Simulates the bit shuffle at 0x401074
    Original bits: 76543210
    New position mapping:
    """
    r8 = 0
    
    if byte_val & 0x01: r8 |= 0x20  # bit 0 -> bit 5
    if byte_val & 0x02: r8 |= 0x40  # bit 1 -> bit 6
    if byte_val & 0x04: r8 |= 0x80  # bit 2 -> bit 7
    if byte_val & 0x08: r8 |= 0x01  # bit 3 -> bit 0
    if byte_val & 0x10: r8 |= 0x02  # bit 4 -> bit 1
    if byte_val & 0x20: r8 |= 0x04  # bit 5 -> bit 2
    if byte_val & 0x40: r8 |= 0x08  # bit 6 -> bit 3
    if byte_val & 0x80: r8 |= 0x10  # bit 7 -> bit 4
    
    return r8

# Test with some values
print("\nBit shuffle examples:")
for test_val in [0x41, 0x42, 0x61, 0x00, 0xff]:
    shuffled = bit_shuffle(test_val)
    print(f"  {test_val:02x} ({test_val:3d}, '{chr(test_val) if 32 <= test_val < 127 else '?'}') -> {shuffled:02x} ({shuffled:3d})")
