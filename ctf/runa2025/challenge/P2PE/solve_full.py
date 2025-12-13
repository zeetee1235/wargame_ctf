#!/usr/bin/env python3
from z3 import *

c = [Int(f'c{i}') for i in range(32)]

solver = Solver()

# printable ASCII
for i in range(32):
    solver.add(And(c[i] >= 0x20, c[i] <= 0x7e))

# 모든 제약 조건 추가
solver.add(c[0] + c[1] + c[2] + c[3] == 0x17d)

# XOR 제약 - 비트 연산을 수동으로
# c[4] ^ c[5] ^ c[6] ^ c[7] == 0x4c
# XOR의 특성: a ^ b = c => a = b ^ c
# 일단 생략하고 다른 제약만

solver.add(c[8] + c[9]*2 - c[10] == 0xe4)

# c[11] ^ (c[12] + c[13]) == 0xe6
# 생략

# (c[14] + c[15] + c[16] + c[17]) % 256 == 0x53
solver.add((c[14] + c[15] + c[16] + c[17]) % 256 == 0x53)

# (c[18]*2 + c[19]) % 256 == 0x35
solver.add((c[18]*2 + c[19]) % 256 == 0x35)

# c[20] ^ (c[21] + 0x12) == 0x1b
# 생략

# c[22] + (c[23] ^ 0x37) == 0xa3
# 생략

# (c[24] + c[25] + c[26]) % 256 == 0x5b
solver.add((c[24] + c[25] + c[26]) % 256 == 0x5b)

# c[27] ^ c[28] ^ c[29] == 0x62
# 생략

# (c[30] + c[31]*3) % 256 == 0x0b
solver.add((c[30] + c[31]*3) % 256 == 0x0b)

# 짝수/홀수 합
even_sum = Sum([c[i] for i in range(0, 32, 2)])
solver.add(even_sum == 0x6bf)

odd_sum = Sum([c[i] for i in range(1, 32, 2)])
solver.add(odd_sum == 0x5a8)

print("Solving...")
import time
start = time.time()

if solver.check() == sat:
    print(f"Solution found in {time.time()-start:.2f}s\n")
    model = solver.model()
    flag_middle = ''.join(chr(model[c[i]].as_long()) for i in range(32))
    flag = "runa2025{" + flag_middle + "}"
    print(f"FLAG: {flag}\n")
    
    # 테스트
    print("Testing with wine...")
    import subprocess
    result = subprocess.run(
        ['wine', 'prob_fixed2.exe'],
        input=flag.encode(),
        capture_output=True,
        timeout=5
    )
    output = result.stdout.decode('utf-8', errors='ignore')
    if "Correct" in output:
        print("✅ FLAG IS CORRECT!")
    elif "Wrong" in output:
        print("❌ Still wrong, need more constraints...")
    else:
        print(f"Output: {output[-100:]}")
else:
    print("No solution")
