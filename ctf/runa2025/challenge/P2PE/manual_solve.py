#!/usr/bin/env python3
import itertools

# 플래그 길이: 42 = runa2025{32 chars}
# 제약 조건들을 하나씩 풀어보자

# 가능한 ASCII printable 범위
def get_chars():
    return range(0x20, 0x7f)  # 공백부터 ~까지

# c[0] + c[1] + c[2] + c[3] = 381
# 평균 95.25 -> 대략 대문자, 소문자, 숫자 영역
# 일반적인 플래그는 소문자 + 숫자 + 특수문자

# 먼저 간단한 솔루션을 시도
# 예를 들어 평균적으로 분포된 값들

# 중간 값으로 시작 (a-z, 0-9, _등)
import string

def try_solve():
    # 일반적인 플래그 문자들
    common_chars = string.ascii_letters + string.digits + '_'
    
    # c[0] + c[1] + c[2] + c[3] = 381인 조합 찾기
    print("Finding solutions for c[0]+c[1]+c[2]+c[3]=381...")
    solutions_0123 = []
    for c0 in common_chars:
        for c1 in common_chars:
            for c2 in common_chars:
                c3_target = 381 - ord(c0) - ord(c1) - ord(c2)
                if 0x20 <= c3_target <= 0x7e:
                    c3 = chr(c3_target)
                    if c3 in common_chars:
                        solutions_0123.append((c0, c1, c2, c3))
                        if len(solutions_0123) < 10:
                            print(f"  Found: {c0}{c1}{c2}{c3}")
    
    print(f"Total solutions for c[0:4]: {len(solutions_0123)}")
    
    # 첫 몇 개 솔루션으로 계속 시도
    for sol in solutions_0123[:10]:
        print(f"\nTrying with c[0:4] = {sol}")
        # 이제 c[4]^c[5]^c[6]^c[7] = 0x4c 찾기
        for c4 in common_chars:
            for c5 in common_chars:
                for c6 in common_chars:
                    c7_target = 0x4c ^ ord(c4) ^ ord(c5) ^ ord(c6)
                    if 0x20 <= c7_target <= 0x7e and chr(c7_target) in common_chars:
                        c7 = chr(c7_target)
                        print(f"  c[4:8] = {c4}{c5}{c6}{c7}")
                        # 이정도면 충분... 너무 많음
                        return

try_solve()
