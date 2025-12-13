#!/usr/bin/env python3
from z3 import *

# XOR 함수 구현
def xor8(a, b):
    """8비트 XOR 연산"""
    result = 0
    for i in range(8):
        bit_a = If((a >> i) & 1 == 1, 1, 0)
        bit_b = If((b >> i) & 1 == 1, 1, 0)
        result += If(bit_a != bit_b, 2**i, 0)
    return result

c = [Int(f'c{i}') for i in range(32)]

solver = Solver()

# printable ASCII
for i in range(32):
    solver.add(And(c[i] >= 0x20, c[i] <= 0x7e))

# 제약 조건
solver.add(c[0] + c[1] + c[2] + c[3] == 0x17d)

# XOR 제약 조건들
# c[4] ^ c[5] ^ c[6] ^ c[7] == 0x4c
xor_result = xor8(xor8(xor8(c[4], c[5]), c[6]), c[7])
solver.add(xor_result == 0x4c)

solver.add(c[8] + c[9]*2 - c[10] == 0xe4)

# c[11] ^ (c[12] + c[13]) == 0xe6
solver.add(xor8(c[11], c[12] + c[13]) == 0xe6)

solver.add((c[14] + c[15] + c[16] + c[17]) % 256 == 0x53)
solver.add((c[18]*2 + c[19]) % 256 == 0x35)

# c[20] ^ (c[21] + 0x12) == 0x1b
solver.add(xor8(c[20], c[21] + 0x12) == 0x1b)

# c[22] + (c[23] ^ 0x37) == 0xa3
solver.add((c[22] + xor8(c[23], 0x37)) % 256 == 0xa3)

solver.add((c[24] + c[25] + c[26]) % 256 == 0x5b)

# c[27] ^ c[28] ^ c[29] == 0x62
solver.add(xor8(xor8(xor8(c[27], c[28]), c[29]), 0) == 0x62)

solver.add((c[30] + c[31]*3) % 256 == 0x0b)

# 짝수/홀수 합
solver.add(Sum([c[i] for i in range(0, 32, 2)]) == 0x6bf)
solver.add(Sum([c[i] for i in range(1, 32, 2)]) == 0x5a8)

print("Solving with all constraints...")
import time
start = time.time()

if solver.check() == sat:
    print(f"Solution found in {time.time()-start:.2f}s\n")
    model = solver.model()
    flag_middle = ''.join(chr(model[c[i]].as_long()) for i in range(32))
    flag = "runa2025{" + flag_middle + "}"
    print(f"🎉 FLAG: {flag}\n")
else:
    print("No solution :(")
