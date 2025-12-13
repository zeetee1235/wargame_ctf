#!/usr/bin/env python3
"""
P2PE 플래그 역산 스크립트
"""
from z3 import *

# 플래그 길이: 42자
# 형식: runa2025{32 characters}

# 고정된 부분
prefix = "runa2025{"
suffix = "}"

# 변수 선언 - BitVec를 사용하여 비트 연산 지원
c = [BitVec(f'c{i}', 8) for i in range(32)]

solver = Solver()

# printable ASCII 범위 제약
for i in range(32):
    solver.add(c[i] >= 0x20)  # space
    solver.add(c[i] <= 0x7e)  # ~

# 제약 조건 추가
solver.add(c[0] + c[1] + c[2] + c[3] == 0x17d)
solver.add(c[4] ^ c[5] ^ c[6] ^ c[7] == 0x4c)
solver.add(c[8] + c[9]*2 - c[10] == 0xe4)
solver.add((c[11] ^ (c[12] + c[13])) == 0xe6)
solver.add((c[14] + c[15] + c[16] + c[17]) & 0xff == 0x53)
solver.add((c[18]*2 + c[19]) & 0xff == 0x35)
solver.add((c[20] ^ (c[21] + 0x12)) & 0xff == 0x1b)
solver.add((c[22] + (c[23] ^ 0x37)) & 0xff == 0xa3)
solver.add((c[24] + c[25] + c[26]) & 0xff == 0x5b)
solver.add((c[27] ^ c[28] ^ c[29]) & 0xff == 0x62)
solver.add((c[30] + c[31]*3) & 0xff == 0x0b)

# 짝수/홀수 인덱스 합
even_sum = c[0]
for i in range(2, 32, 2):
    even_sum = even_sum + c[i]
solver.add(even_sum == 0x6bf)

odd_sum = c[1]
for i in range(3, 32, 2):
    odd_sum = odd_sum + c[i]
solver.add(odd_sum == 0x656)

print("Solving constraints...")
if solver.check() == sat:
    model = solver.model()
    flag_middle = ''.join(chr(model[c[i]].as_long()) for i in range(32))
    flag = prefix + flag_middle + suffix
    print(f"Found flag: {flag}")
    print(f"Flag length: {len(flag)}")
    
    # 검증
    chars_test = [ord(ch) for ch in flag_middle]
    print("\nVerifying constraints:")
    print(f"c[0]+c[1]+c[2]+c[3] = {chars_test[0]+chars_test[1]+chars_test[2]+chars_test[3]} (expected 0x17d={0x17d})")
    print(f"c[4]^c[5]^c[6]^c[7] = {chars_test[4]^chars_test[5]^chars_test[6]^chars_test[7]} (expected 0x4c={0x4c})")
    print(f"Even sum = {sum(chars_test[i] for i in range(0, 32, 2))} (expected 0x6bf={0x6bf})")
    print(f"Odd sum = {sum(chars_test[i] for i in range(1, 32, 2))} (expected 0x656={0x656})")
else:
    print("No solution found!")
