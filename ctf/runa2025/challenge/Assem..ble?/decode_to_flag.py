#!/usr/bin/env python3
"""
pula0605를 runa2025로 매핑하여 플래그 찾기
"""

encoded = b'pula0605{a142ace93d9255`ea57c4cc4`7e`a024d'

# 매핑 규칙 찾기
# p -> r
# u -> u  
# l -> n
# a -> a
# 0 -> 2
# 6 -> 0
# 0 -> 2
# 5 -> 5

# 각 문자별 매핑 구축
mapping = {}

# pula -> runa
mapping[ord('p')] = ord('r')
mapping[ord('u')] = ord('u')
mapping[ord('l')] = ord('n')
mapping[ord('a')] = ord('a')

# 0605 -> 2025
mapping[ord('0')] = ord('2')
mapping[ord('6')] = ord('0')
# 0은 이미 2로 매핑됨
mapping[ord('5')] = ord('5')

print("기본 매핑:")
for k, v in sorted(mapping.items()):
    print(f"  {chr(k)} -> {chr(v)}")

# 하지만 '0'이 두 번 나오는데 다른 값으로 매핑되므로... 위치 기반일 수 있음
# 다시 분석: pula0605
# p(0) -> r: +2
# u(1) -> u: +0
# l(2) -> n: +2
# a(3) -> a: +0
# 0(4) -> 2: +2
# 6(5) -> 0: -6
# 0(6) -> 2: +2
# 5(7) -> 5: +0

print("\n위치별 패턴:")
print("짝수 위치 (0,2,4,6): +2")
print("홀수 위치 (1,3,7): +0")
print("위치 5: -6")

def decode_position_based(data):
    """위치 기반 디코딩"""
    result = bytearray()
    for i, b in enumerate(data):
        if i == 5:
            result.append((b - 6) & 0xff)
        elif i % 2 == 0:
            result.append((b + 2) & 0xff)
        else:
            result.append(b)
    return bytes(result)

decoded1 = decode_position_based(encoded)
print(f"\n위치 기반 디코딩 시도 1:")
print(f"  {decoded1}")

# 좀 더 복잡한 패턴일 수 있음
# backtick (`) 문자들을 주목: 위치 22, 30, 33, 35
# ` (0x60) 

# 혹시 모든 문자에 대한 완전한 매핑을 찾아야 할까?
print("\n" + "="*70)
print("전체 문자 분석:")
print("="*70)

unique_chars = sorted(set(encoded))
print(f"Unique characters: {[chr(c) if 32 <= c < 127 else f'\\x{c:02x}' for c in unique_chars]}")

# 만약 runa2025{로 시작한다면, 처음 9글자의 매핑을 알 수 있음
expected_start = b"runa2025{"
actual_start = encoded[:9]

print(f"\nExpected: {expected_start}")
print(f"Actual:   {actual_start}")
print("\nCharacter mapping from first 9 chars:")

char_map = {}
for i in range(9):
    char_map[actual_start[i]] = expected_start[i]
    print(f"  {chr(actual_start[i])} (0x{actual_start[i]:02x}) -> {chr(expected_start[i])} (0x{expected_start[i]:02x})")

# 이 매핑을 나머지에 적용
print("\n" + "="*70)
print("매핑 적용:")
print("="*70)

decoded = bytearray()
for b in encoded:
    if b in char_map:
        decoded.append(char_map[b])
    else:
        # 아직 매핑되지 않은 문자 - 패턴 추정
        # ` (96) 는 뭘까?
        # 1(49), 2(50), 3(51), 4(52), 5(53), 7(55), 9(57) - 숫자들
        # c(99), d(100), e(101) - 소문자
        
        # 추측: 소문자와 숫자는 그대로, ` 만 특별
        if b == ord('`'):
            # ` 는 보통 }의 이전 문자... 혹시 _?
            decoded.append(ord('_'))
        else:
            decoded.append(b)

print(f"Result: {bytes(decoded)}")

# 다른 시도: ` 를 다른 문자로
for replacement in [ord('}'), ord('_'), ord('-'), ord('.'), ord('b'), ord('f')]:
    test_decoded = bytearray()
    for b in encoded:
        if b in char_map:
            test_decoded.append(char_map[b])
        elif b == ord('`'):
            test_decoded.append(replacement)
        else:
            test_decoded.append(b)
    
    result = bytes(test_decoded)
    if b'runa2025{' in result:
        print(f"\nWith ` -> {chr(replacement)}: {result}")
