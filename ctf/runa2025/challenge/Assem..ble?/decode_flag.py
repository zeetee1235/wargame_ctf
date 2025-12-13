#!/usr/bin/env python3
"""
pula0605{a142ace93d9255`ea57c4cc4`7e`a024d
이것이 인코딩된 플래그일 가능성 체크
"""

encoded = b'pula0605{a142ace93d9255`ea57c4cc4`7e`a024d'

print(f"Encoded: {encoded}")
print(f"Length: {len(encoded)}")
print()

# Try XOR with common values
print("="*70)
print("XOR 시도:")
print("="*70)

for xor_val in range(256):
    decoded = bytes([b ^ xor_val for b in encoded])
    
    # Check if it starts with "runa2025{"
    if decoded.startswith(b'runa2025{') or decoded.startswith(b'RUNA2025{'):
        print(f"\nXOR {xor_val:3d} (0x{xor_val:02x}): {decoded}")
        if b'}' in decoded:
            print("  >>> Contains closing brace!")

# Try ROT
print("\n" + "="*70)
print("ROT 시도 (letters only):")
print("="*70)

for rot in range(1, 26):
    decoded = bytearray()
    for b in encoded:
        if 65 <= b <= 90:  # A-Z
            decoded.append(((b - 65 + rot) % 26) + 65)
        elif 97 <= b <= 122:  # a-z
            decoded.append(((b - 97 + rot) % 26) + 97)
        else:
            decoded.append(b)
    
    if decoded.startswith(b'runa2025{') or decoded.startswith(b'RUNA2025{'):
        print(f"\nROT{rot:2d}: {bytes(decoded)}")

# Try adding/subtracting
print("\n" + "="*70)
print("ADD/SUB 시도:")
print("="*70)

for add_val in range(-50, 50):
    decoded = bytes([(b + add_val) & 0xff for b in encoded])
    
    if decoded.startswith(b'runa2025{') or decoded.startswith(b'RUNA2025{'):
        print(f"\nADD {add_val:3d}: {decoded}")

# Check character by character difference
print("\n" + "="*70)
print("문자별 차이 분석:")
print("="*70)

expected = b"runa2025"
actual = encoded[:8]

print("Expected | Actual | Diff (dec) | Diff (hex)")
print("-" * 50)
for i in range(8):
    if i < len(expected) and i < len(actual):
        diff = actual[i] - expected[i]
        print(f"  {chr(expected[i])}      |   {chr(actual[i])}    |   {diff:4d}     |   0x{diff & 0xff:02x}")

# Maybe it's a simple substitution?
print("\n" + "="*70)
print("추측: p->r, u->u, l->n, a->a 매핑?")
print("="*70)

# Build mapping
mapping = {
    ord('p'): ord('r'),
    ord('u'): ord('u'),  
    ord('l'): ord('n'),
    ord('a'): ord('a'),
    ord('0'): ord('2'),
    ord('6'): ord('0'),
    ord('5'): ord('2'),
}

# The differences suggest: p=112, r=114 (diff=+2)
# But this doesn't hold for all...

# Let me check bit patterns
print("\n비트 패턴 분석:")
print("-" * 50)
for i in range(min(8, len(encoded))):
    e = expected[i] if i < len(expected) else 0
    a = encoded[i]
    print(f"{chr(e) if 32<=e<127 else '?'} = 0x{e:02x} = {e:08b}")
    print(f"{chr(a) if 32<=a<127 else '?'} = 0x{a:02x} = {a:08b}")
    print(f"XOR = 0x{e^a:02x} = {e^a:08b}")
    print()
