#!/usr/bin/env python3
"""
완전한 문자 매핑 찾기
문제의 bit shuffle 알고리즘을 역으로 이용
"""

# 우리가 알고 있는 정보:
# pula0605{a142ace93d9255`ea57c4cc4`7e`a024d (42글자) = Correct
# 이것은 runa2025{...} 형태의 플래그일 것

encoded = b'pula0605{a142ace93d9255`ea57c4cc4`7e`a024d'

# 알려진 매핑:
# pula0605{ -> runa2025{

# 추가 힌트: 마지막이 d로 끝남
# CTF 플래그는 보통 }로 끝나므로
# d -> }일 가능성

# 완전한 문자 매핑 구축
# ASCII 값 차이를 보자
print("="*70)
print("문자별 ASCII 차이 분석:")
print("="*70)

known_mappings = [
    ('p', 'r'),  # 112 -> 114 (+2)
    ('u', 'u'),  # 117 -> 117 (0)
    ('l', 'n'),  # 108 -> 110 (+2)
    ('a', 'a'),  # 97 -> 97 (0)
    ('0', '2'),  # 48 -> 50 (+2)
    ('6', '0'),  # 54 -> 48 (-6)
    ('0', '2'),  # 48 -> 50 (+2) again
    ('5', '5'),  # 53 -> 53 (0)
    ('{', '{'),  # 123 -> 123 (0)
]

for enc_char, dec_char in known_mappings:
    diff = ord(dec_char) - ord(enc_char)
    print(f"  {enc_char} -> {dec_char}: diff = {diff:+3d}")

# 패턴: +2, 0, +2, 0, +2, -6, +2, 0, 0
# 이것은 bit shuffle과 관련이 있을까?

# 실제로 전체 문자 집합을 보면:
# '0', '1', '2', '3', '4', '5', '6', '7', '9', '`', 'a', 'c', 'd', 'e', 'l', 'p', 'u', '{'

# 플래그 형식을 고려하면:
# runa2025{...} 
# 일반적으로 소문자, 숫자, 언더스코어

# ` (96) 는 아마 _ (95)의 변형? 차이 +1
# 하지만 위의 패턴과 맞지 않음

# 다른 접근: 모든 문자에 대해 bit_shuffle의 역을 적용?
# 아니면 더 간단하게, 단순 치환 암호?

# 만약 d -> } 라면:
# d(100) -> }(125): 차이 +25

# 전체 유추:
# - 숫자와 소문자는 대부분 그대로거나 작은 shift
# - ` 는 특수문자 (_, }, 등)
# - d는 }?

# 모든 조합 시도
import itertools

possible_for_backtick = ['_', '}', '-', '.', '!', '#', '$']
possible_for_d_at_end = ['}', 'd']
possible_for_0_repeated = ['0', '2']

print("\n" + "="*70)
print("가능한 플래그 조합:")
print("="*70)

# 기본 매핑
base_map = {
    ord('p'): ord('r'),
    ord('u'): ord('u'),
    ord('l'): ord('n'),
    ord('a'): ord('a'),
    ord('6'): ord('0'),
    ord('5'): ord('5'),
    ord('{'): ord('{'),
    # 숫자들은 그대로 유지 시도
    ord('1'): ord('1'),
    ord('2'): ord('2'),
    ord('3'): ord('3'),
    ord('4'): ord('4'),
    ord('7'): ord('7'),
    ord('9'): ord('9'),
    ord('c'): ord('c'),
    ord('e'): ord('e'),
}

# 문제가 되는 문자들:
# 0: 여러 곳에 등장, 어떤 건 2, 어떤 건 0
# `: _나 다른 문자
# d: 끝에 있으므로 }일 가능성

# 0의 위치별 분석
print("\n'0' 문자 위치 분석:")
for i, c in enumerate(encoded):
    if c == ord('0'):
        print(f"  Position {i}: '0'")

# 위치: 4, 6 (pula0605에서)
# 그리고 더 있을 수 있음

# 간단한 시도: 모든 0을 2로
test_map = base_map.copy()
test_map[ord('0')] = ord('2')
test_map[ord('`')] = ord('_')
test_map[ord('d')] = ord('}')

decoded = bytes([test_map.get(b, b) for b in encoded])
print(f"\n시도 1 (0->2, `->_, d->}}):")
print(f"  {decoded}")

# 0을 다르게
test_map2 = base_map.copy()
test_map2[ord('0')] = ord('0')
test_map2[ord('`')] = ord('_')
test_map2[ord('d')] = ord('}')
decoded2 = bytes([test_map2.get(b, b) for b in encoded])
print(f"\n시도 2 (0->0, `->_, d->}}):")
print(f"  {decoded2}")

# 혹시 '0'이 문맥에 따라 다를까?
# 위치 4,6의 '0'은 '2', 나머지는 '0'?
print("\n시도 3 (위치별 0 매핑):")
decoded3 = bytearray()
for i, b in enumerate(encoded):
    if b == ord('0') and i in [4, 6]:  # pula0605의 0들
        decoded3.append(ord('2'))
    elif b == ord('`'):
        decoded3.append(ord('_'))
    elif b == ord('d'):
        decoded3.append(ord('}'))
    else:
        decoded3.append(base_map.get(b, b))
print(f"  {bytes(decoded3)}")

# 플래그는 보통 의미있는 단어를 포함
# 더 많은 조합 시도
for backtick_char in ['_', '-', '.']:
    for d_char in ['}', 'd']:
        for zero_char in ['0', '2']:
            test_map = base_map.copy()
            test_map[ord('0')] = ord(zero_char)
            test_map[ord('`')] = ord(backtick_char)
            test_map[ord('d')] = ord(d_char)
            
            decoded = bytes([test_map.get(b, b) for b in encoded])
            
            # }로 끝나는지 확인
            if decoded.endswith(b'}'):
                print(f"\n⭐ Candidate (0->{zero_char}, `->{backtick_char}, d->{d_char}):")
                print(f"    {decoded}")
