#!/usr/bin/env python3

encoded = 'pula0605{a142ace93d9255`ea57c4cc4`7e`a024d'

# 기본 매핑
base_map = {
    'p': 'r', 'u': 'u', 'l': 'n', 'a': 'a',
    '0': '2', '6': '0', '5': '5',
    '1': '1', '2': '2', '3': '3', '4': '4', 
    '7': '7', '9': '9',
    'c': 'c', 'e': 'e', 'd': 'd',
    '{': '{', '`': '_'
}

print("=== 가능한 플래그 후보들 ===\n")

# 후보 1: 마지막 d만 }로
flag1 = ''.join(base_map.get(c, c) for c in encoded[:-1]) + '}'
print("1. 마지막 d -> } (현재):")
print(f"   {flag1}\n")

# 후보 2: 모든 d를 }로?
flag2 = ''.join(base_map.get(c, c) if c != 'd' else '}' for c in encoded)
print("2. 모든 d -> }:")
print(f"   {flag2}\n")

# 후보 3: 024d 부분을 다르게 해석
# a024d를 a226f로? (각 숫자 +2, d->f)
temp = encoded[:-4]  # ...7e`까지
decoded_temp = ''.join(base_map.get(c, c) for c in temp)
print(f"3. 마지막 4글자 다른 변환:")
print(f"   3-1 (024d -> 246f): {decoded_temp}_a246f")
print(f"   3-2 (024d -> 226): {decoded_temp}_a226" + "}")
print(f"   3-3 (a024d -> c246): {decoded_temp}_c246" + "}")
print()

# 후보 4: `를 다른 문자로?
print(f"4. backtick을 다른 문자로:")
for bt_char in ['_', '-', '.']:
    map_v = {**base_map, '`': bt_char}
    flag4 = ''.join(map_v.get(c, c) for c in encoded[:-1]) + '}'
    print(f"   ` -> '{bt_char}': {flag4}")
print()

# 후보 5: 숫자 변환 규칙 재검토
# 0->2 (+2), 6->0 (-6)인데, 다른 숫자는?
print(f"5. 다른 숫자 변환 규칙:")
# 4가 6으로?
num_map2 = {**base_map, '4': '6'}
flag5_1 = ''.join(num_map2.get(c, c) for c in encoded[:-1]) + '}'
print(f"   5-1 (4 -> 6): {flag5_1}")

# 2가 4로?
num_map3 = {**base_map, '2': '4'}
flag5_2 = ''.join(num_map3.get(c, c) for c in encoded[:-1]) + '}'
print(f"   5-2 (2 -> 4): {flag5_2}")
print()

# 후보 6: 전체를 다시 생각 - 실제 runa2025로 시작하는지 확인
print(f"6. 검증: 모두 runa2025{{로 시작하는가?")
all_flags = [flag1, flag2, flag5_1, flag5_2]
for i, f in enumerate(all_flags, 1):
    print(f"   후보{i}: {f.startswith('runa2025{')}")
