#!/usr/bin/env python3
from z3 import *

# 정수 변수 사용 (더 빠름)
c = [Int(f'c{i}') for i in range(32)]

solver = Solver()

# printable ASCII 범위
for i in range(32):
    solver.add(And(c[i] >= 0x20, c[i] <= 0x7e))

# 제약 조건 (r2 디스어셈블리에서 정확히 추출)
solver.add(c[0] + c[1] + c[2] + c[3] == 0x17d)

# XOR 제약 - 수동 계산
# c[4] ^ c[5] ^ c[6] ^ c[7] = 0x4c
# 이건 나중에 추가

solver.add(c[8] + c[9]*2 - c[10] == 0xe4)

# c[11] ^ (c[12] + c[13]) = 0xe6
# 나중에 추가

solver.add((c[14] + c[15] + c[16] + c[17]) % 256 == 0x53)
solver.add((c[18]*2 + c[19]) % 256 == 0x35)

# c[20] ^ (c[21] + 0x12) = 0x1b
# 나중에

solver.add((c[22] + (c[23] % 256)) % 256 == 0xa3 - 0x37)  # 간소화
solver.add((c[24] + c[25] + c[26]) % 256 == 0x5b)

# c[27] ^ c[28] ^ c[29] = 0x62
# 나중에

solver.add((c[30] + c[31]*3) % 256 == 0x0b)

# 짝수/홀수 합 (가장 중요!)
solver.add(Sum([c[i] for i in range(0, 32, 2)]) == 0x6bf)
solver.add(Sum([c[i] for i in range(1, 32, 2)]) == 0x5a8)  # 수정된 값!

print("Solving...")
import time
start = time.time()
if solver.check() == sat:
    model = solver.model()
    chars = [model[c[i]].as_long() for i in range(32)]
    flag_middle = ''.join(chr(ch) for ch in chars)
    flag = "runa2025{" + flag_middle + "}"
    print(f"\nFound in {time.time()-start:.2f}s:")
    print(flag)
    print(f"Length: {len(flag)}")
    
    # 검증
    print("\nVerifying:")
    print(f"sum(c[0:4]) = {sum(chars[0:4])} (expected {0x17d})")
    print(f"Even sum = {sum(chars[i] for i in range(0, 32, 2))} (expected {0x6bf})")
    print(f"Odd sum = {sum(chars[i] for i in range(1, 32, 2))} (expected {0x5a8})")
else:
    print(f"No solution after {time.time()-start:.2f}s")
