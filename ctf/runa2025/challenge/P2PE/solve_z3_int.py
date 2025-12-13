#!/usr/bin/env python3
from z3 import *

# 정수 변수 사용 (비트 연산은 수동으로)
c = [Int(f'c{i}') for i in range(32)]

solver = Solver()

# printable ASCII
for i in range(32):
    solver.add(And(c[i] >= 0x20, c[i] <= 0x7e))

# 간단한 제약 조건만 먼저
solver.add(c[0] + c[1] + c[2] + c[3] == 0x17d)
solver.add(c[8] + c[9]*2 - c[10] == 0xe4)

# 짝수/홀수 합
even_sum = Sum([c[i] for i in range(0, 32, 2)])
solver.add(even_sum == 0x6bf)

odd_sum = Sum([c[i] for i in range(1, 32, 2)])
solver.add(odd_sum == 0x5a8)

print("Solving with reduced constraints...")
import time
start = time.time()

if solver.check() == sat:
    print(f"Solution found in {time.time()-start:.2f}s")
    model = solver.model()
    flag_middle = ''.join(chr(model[c[i]].as_long()) for i in range(32))
    flag = "runa2025{" + flag_middle + "}"
    print(f"\nPartial solution: {flag}")
    
    # 검증
    chars = [ord(ch) for ch in flag_middle]
    print(f"\nVerification:")
    print(f"sum(c[0:4]) = {sum(chars[0:4])} (expected 381)")
    print(f"Even sum = {sum(chars[i] for i in range(0, 32, 2))} (expected 1727)")
    print(f"Odd sum = {sum(chars[i] for i in range(1, 32, 2))} (expected 1448)")
else:
    print("No solution")
