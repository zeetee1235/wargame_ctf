#!/usr/bin/env python3
import struct
from pathlib import Path

"""
Reconstructs the comparison string by following the pointer list observed in .data,
which points into .rodata (file offsets match virtual addresses here).

Derived offsets from `readelf -x .data`:
  0x00020010: 0x00001038, 0x00001040, 0x00001048, 0x00001050,
  0x00020020: 0x00001058, 0x00001060, 0x00001058, 0x00001068,
  0x00020030: 0x00001070, 0x00001078, 0x00001050, 0x00001048,
  0x00020040: 0x00001080, 0x00001088, 0x00001090, 0x00001040,
  0x00020050: 0x00001080, 0x00001038, 0x00001098, 0x00001050,
  0x00020060: 0x000010a0, 0x00001080, 0x00001080, 0x000010a8,
  0x00020070: 0x00001090, 0x000010a0, 0x000010b0, 0x00001080,
  0x00020080: 0x000010a0, 0x00001050, 0x000010b8, 0x00001050,
  0x00020090: 0x00001080, 0x00001048, 0x00001080, 0x00001048,
  0x000200a0: 0x000010b0, 0x000010c8, 0x000010d0, 0x000010c0,
  0x000200b0: 0x000010b0, 0x00001080, 0x00001038, 0x000010b0,
  0x000200c0: 0x000010d8, 0x000010e0

We will read one byte at each listed offset and assemble the string.
"""

OFFSETS = [
    0x00001038, 0x00001040, 0x00001048, 0x00001050,
    0x00001058, 0x00001060, 0x00001058, 0x00001068,
    0x00001070, 0x00001078, 0x00001050, 0x00001048,
    0x00001080, 0x00001088, 0x00001090, 0x00001040,
    0x00001080, 0x00001038, 0x00001098, 0x00001050,
    0x000010a0, 0x00001080, 0x00001080, 0x000010a8,
    0x00001090, 0x000010a0, 0x000010b0, 0x00001080,
    0x000010a0, 0x00001050, 0x000010b8, 0x00001050,
    0x00001080, 0x00001048, 0x00001080, 0x00001048,
    0x000010b0, 0x000010c8, 0x000010d0, 0x000010c0,
    0x000010b0, 0x00001080, 0x00001038, 0x000010b0,
    0x000010d8, 0x000010e0,
]

def read_bytes(path: Path, offsets):
    data = path.read_bytes()
    chars = []
    for off in offsets:
        if off < 0 or off >= len(data):
            raise ValueError(f"Offset out of range: {off:#x}")
        b = data[off]
        chars.append(chr(b))
    return ''.join(chars)

def main():
    bin_path = Path(__file__).with_name('prob')
    s = read_bytes(bin_path, OFFSETS)
    print(s)

if __name__ == '__main__':
    main()
