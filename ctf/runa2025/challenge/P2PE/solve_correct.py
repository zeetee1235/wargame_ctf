#!/usr/bin/env python3
from z3 import *

prefix = "runa2025{"
suffix = "}"

# BitVec 사용
c = [BitVec(f'c{i}', 16) for i in range(32)]

solver = Solver()

# printable ASCII 범위
for i in range(32):
    solver.add(c[i] >= 0x20)
    solver.add(c[i] <= 0x7e)

# 제약 조건
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

# 짝수/홀수 합 (정확한 값!)
even_sum = Sum([c[i] for i in range(0, 32, 2)])
solver.add(even_sum == 0x6bf)  # 1727

odd_sum = Sum([c[i] for i in range(1, 32, 2)])
solver.add(odd_sum == 0x5a8)  # 1448 (NOT 0x656!)

print("Solving...")
if solver.check() == sat:
    model = solver.model()
    flag_middle = ''.join(chr(model[c[i]].as_long()) for i in range(32))
    flag = prefix + flag_middle + suffix
    print(f"\n🎉 FLAG FOUND: {flag}\n")
    print(f"Length: {len(flag)}")
else:
    print("No solution!")
