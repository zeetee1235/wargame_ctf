#!/usr/bin/env python3
"""
P2PE 플래그 복원 스크립트
디스어셈블리에서 발견한 문자 비교 로직을 기반으로 플래그 복원
"""

# 직접 비교되는 문자들
flag = ['?'] * 50  # 충분히 큰 배열

# 직접 비교 (순서대로)
flag[0] = 'r'   # cmp $0x72
flag[1] = 'u'   # cmp $0x75
flag[2] = 'n'   # cmp $0x6e
flag[3] = 'a'   # cmp $0x61
flag[4] = '2'   # cmp $0x32
flag[5] = '0'   # cmp $0x30
flag[6] = '2'   # cmp $0x32
flag[7] = '5'   # cmp $0x35
flag[8] = '{'   # cmp $0x7b
# flag[39] = '}'  # cmp $0x7d (마지막 문자)

# 더 많은 비교 로직을 디스어셈블리에서 추출
print("Extracting all character comparisons from disassembly...")

import subprocess

# objdump로 전체 비교 로직 추출
result = subprocess.run(
    ['objdump', '-d', 'prob_fixed.exe'],
    capture_output=True,
    text=True,
    stderr=subprocess.DEVNULL
)

lines = result.stdout.split('\n')

# 문자 비교 패턴 찾기
comparisons = []
for i, line in enumerate(lines):
    if 'cmp' in line and '%eax' in line:
        # cmp $0x??, %eax 형식
        if '$0x' in line:
            parts = line.split('$0x')
            if len(parts) > 1:
                hex_val = parts[1].split(',')[0].strip()
                try:
                    val = int(hex_val, 16)
                    if 32 <= val < 127:  # ASCII 범위
                        char = chr(val)
                        # 이전 몇 줄 확인하여 인덱스 추출
                        context = '\n'.join(lines[max(0, i-5):i+2])
                        comparisons.append((val, char, context))
                except:
                    pass

print(f"\nFound {len(comparisons)} ASCII comparisons:")
for val, char, _ in comparisons[:30]:
    print(f"  0x{val:02x} = '{char}'")

# 간단한 순서로 플래그 조합
simple_flag = 'runa2025{'
for val, char, context in comparisons[9:]:  # runa2025{ 이후
    if char != '}':
        simple_flag += char
    else:
        simple_flag += '}'
        break

print(f"\nSimple reconstruction: {simple_flag}")

# 더 정확한 분석을 위해 XOR/ADD 연산도 고려
# 일단 기본 플래그 출력
print("\n" + "="*60)
print("Based on the character comparisons found:")
print(f"Flag prefix: runa2025{{")
print(f"Flag suffix: }}")
print("="*60)

