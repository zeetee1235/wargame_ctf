#!/usr/bin/env python3
"""
Re-verify .data pointer list by parsing the hex dump directly.
"""
from pathlib import Path
import struct

def main():
    bin_path = Path(__file__).with_name('prob')
    data = bin_path.read_bytes()
    
    # .data section starts at file offset 0x10000 (from readelf)
    # Virtual address 0x00020000 -> file offset 0x10000
    data_start = 0x10000
    
    # Looking at the dump, pointers start at 0x00020010
    # which is file offset 0x10010
    ptr_start = 0x10010
    
    # Read pointers (8 bytes each, little-endian)
    pointers = []
    offset = ptr_start
    
    # Read until we hit end of meaningful data (around 0x00020188)
    while offset < 0x10188:
        ptr_bytes = data[offset:offset+8]
        if len(ptr_bytes) < 8:
            break
        ptr = struct.unpack('<Q', ptr_bytes)[0]
        
        # Stop if we hit null or out of .rodata range
        if ptr == 0:
            break
        # .rodata is 0x1000-0x10e2
        if ptr < 0x1000 or ptr > 0x10ff:
            break
            
        pointers.append(ptr)
        offset += 8
    
    print(f"Found {len(pointers)} pointers:")
    for i, ptr in enumerate(pointers):
        if i % 4 == 0:
            print()
        print(f"  0x{ptr:08x}", end='')
    print("\n")
    
    # Now read the characters at each pointer
    chars = []
    for ptr in pointers:
        # These are virtual addresses in .rodata
        # .rodata starts at vaddr 0x00001000, file offset 0x1000
        file_offset = ptr
        if file_offset < len(data):
            ch = chr(data[file_offset])
            chars.append(ch)
        else:
            chars.append('?')
    
    result = ''.join(chars)
    print(f"Reconstructed string ({len(result)} chars):")
    print(result)

if __name__ == '__main__':
    main()
