#!/usr/bin/env python3
import struct

# Full hex dump from readelf
hex_lines = """
  0x00402000 4eaed130 561656b6 6f3036d6 963070b0 
  0x00402010 3776d037 96b6b650 b030b6f6 70d67070 
  0x00402020 d650f6b0 50305696 d6d07050 96761730 
  0x00402030 569650d6 96b63096 90d63717 3090d050 
  0x00402040 70969696 1656f676 3716f690 90505017 
  0x00402050 b63070b0 b016d017 3696d637 56309637 
  0x00402060 1730f6d6 30f676b0 76d6d637 5690b0f6 
  0x00402070 d637d076 d0d630f6 305677b6 16b0d670 
  0x00402080 30d09030 70b096d6 56af2af4 5800bec0 
  0x00402090 7621c3cd 32163c6c c032d219 0e226360 
  0x004020a0 0d74cbeb b50f3865 6a3e7c10 3b45bc2c 
  0x004020b0 eb8ee25a a5e4e9cc 25dc0ea9 7db0749f 
  0x004020c0 528fa996 b8264b8d 8c4b00b3 4ec4af7e 
  0x004020d0 9d0cf62a 0b8e1b8a 0f7c7fb0 3f57535f 
  0x004020e0 2da41f82 212c0485 604b8e25 84e79482 
  0x004020f0 7a143593 3835e90f 0b6be219 53e88d3a 
  0x00402100 cc4c9ce7 481e3c3e b05ffd5d 25345d86 
  0x00402110 b31e033e 8a204000 00000000 9a204000 
  0x00402120 00000000 aa204000 00000000 ba204000 
  0x00402130 00000000 ca204000 00000000 da204000 
  0x00402140 00000000 ea204000 00000000 fa204000 
  0x00402150 00000000 0a214000 00000000 1a214000 
  0x00402160 00000000 2a214000 00000000 3a214000 
  0x00402170 00000000 4a214000 00000000 5a214000 
  0x00402180 00000000 6a214000 00000000 7a214000 
  0x00402190 00000000 8a214000 00000000 9a214000 
  0x004021a0 00000000 436f7272 65637421 0a496e63 
  0x004021b0 6f727265 6374210a
"""

# Parse hex dump
data = bytearray()
for line in hex_lines.strip().split('\n'):
    parts = line.split()
    if len(parts) < 2:
        continue
    hex_data = ''.join(parts[1:-1])  # Skip address and ASCII
    data.extend(bytes.fromhex(hex_data))

print(f"Total data length: {len(data)} bytes")

# Pointer table starts at 0x402114, which is offset 0x114
ptr_table_offset = 0x114
print(f"\nPointer table at offset 0x{ptr_table_offset:x}:")

tables = []
for i in range(16):
    offset = ptr_table_offset + i * 8
    if offset + 8 <= len(data):
        ptr = struct.unpack('<Q', data[offset:offset+8])[0]
        print(f"  Table[{i:2d}]: 0x{ptr:016x}", end='')
        
        # Extract the actual table data
        if ptr >= 0x402000:
            table_offset = ptr - 0x402000
            if table_offset + 16 <= len(data):
                table_data = data[table_offset:table_offset+16]
                tables.append(table_data)
                print(f" -> offset 0x{table_offset:03x}: {table_data.hex()}")
            else:
                print(f" -> INVALID OFFSET")
                tables.append(None)
        else:
            print(f" -> INVALID POINTER")
            tables.append(None)

print("\n" + "="*70)
print("Algorithm simulation:")
print("="*70)

def bit_shuffle(val):
    """Bit shuffle function from 0x401074"""
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

def process_char(char_val, pos, input_len):
    """Process one character at position pos"""
    # Step 1: Bit shuffle
    r8 = bit_shuffle(char_val)
    print(f"  Pos {pos:2d}: char=0x{char_val:02x} ('{chr(char_val) if 32<=char_val<127 else '?'}') -> shuffle=0x{r8:02x}")
    
    # Step 2: XOR and ADD with r13 (input length)
    r13 = input_len & 0xff
    r8 = (r8 ^ r13) & 0xff
    r8 = (r8 + r13) & 0xff
    print(f"        XOR+ADD with len({r13}): 0x{r8:02x}")
    
    # Step 3: Table lookup
    # r12 = position
    # High nibble selects table, low nibble selects byte in table
    high_nibble = (pos >> 4) & 0xf
    low_nibble = pos & 0xf
    
    # The code does: lea rax,[rax+rax*1+0x1] where rax = pos >> 4
    # So table_index = (high_nibble * 2) + 1
    table_idx = (high_nibble * 2) + 1
    
    print(f"        Table lookup: pos=0x{pos:02x}, high={high_nibble}, low={low_nibble}, table_idx={table_idx}")
    
    if table_idx < len(tables) and tables[table_idx] is not None:
        table_byte = tables[table_idx][low_nibble]
        print(f"        Table[{table_idx}][{low_nibble}] = 0x{table_byte:02x}")
        
        # XOR with table value
        r8 ^= table_byte
        print(f"        After table XOR: 0x{r8:02x}")
    
    return r8

# Test with a sample input
test_input = b"test"
print(f"\nTesting with input: {test_input}")
print(f"Input length: {len(test_input)}")
print()

r14 = 0
for i, char in enumerate(test_input):
    r8 = process_char(char, i, len(test_input))
    r14 |= r8
    print(f"        r14 |= r8 -> r14 = 0x{r14:02x}")
    print()

print(f"Final r14: 0x{r14:02x} (should be 0 for 'Correct!')")
