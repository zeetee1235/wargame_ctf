#!/usr/bin/env python3
"""
Bit shuffle의 역함수를 적용하여 디코딩
"""

def bit_shuffle(val):
    """Original shuffle"""
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

def bit_unshuffle(val):
    """Reverse of bit shuffle"""
    r8 = 0
    # Original: bit 0 -> bit 5, so reverse: bit 5 -> bit 0
    if val & 0x20: r8 |= 0x01  # bit 5 -> bit 0
    if val & 0x40: r8 |= 0x02  # bit 6 -> bit 1
    if val & 0x80: r8 |= 0x04  # bit 7 -> bit 2
    if val & 0x01: r8 |= 0x08  # bit 0 -> bit 3
    if val & 0x02: r8 |= 0x10  # bit 1 -> bit 4
    if val & 0x04: r8 |= 0x20  # bit 2 -> bit 5
    if val & 0x08: r8 |= 0x40  # bit 3 -> bit 6
    if val & 0x10: r8 |= 0x80  # bit 4 -> bit 7
    return r8

# Test
test_chars = [ord('r'), ord('u'), ord('n'), ord('a')]
for c in test_chars:
    shuffled = bit_shuffle(c)
    unshuffled = bit_unshuffle(shuffled)
    print(f"{chr(c)} (0x{c:02x}) -> shuffle: 0x{shuffled:02x} -> unshuffle: 0x{unshuffled:02x} ({chr(unshuffled)})")

print("\n" + "="*70)

# Now try to decode
encoded = b'pula0605{a142ace93d9255`ea57c4cc4`7e`a024d'

print("Trying bit_unshuffle on each character:")
decoded = bytes([bit_unshuffle(b) for b in encoded])
print(f"Result: {decoded}")

print("\n" + "="*70)
print("Maybe the answer IS the flag itself!")
print("Let's test if the 42-byte answer can be used directly:")
print(f"\nTesting: {encoded}")
