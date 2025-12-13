#!/usr/bin/env python3
import angr
import claripy

# PE 파일 로드
proj = angr.Project('./prob_fixed2.exe', auto_load_libs=False)

# 플래그 길이: 42 (runa2025{ + 32 chars + })
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(42)]

# 플래그 문자열 생성
flag = claripy.Concat(*flag_chars)

# 초기 상태 설정 - stdin으로 플래그 입력
state = proj.factory.full_init_state(
    stdin=angr.SimPackets(name='stdin'),
)

# stdin에 symbolic 플래그 추가
for i, char in enumerate(flag_chars):
    state.stdin.store(i, char)
    # printable ASCII 제약
    state.solver.add(char >= 0x20)
    state.solver.add(char <= 0x7e)

# 고정된 부분 추가
state.solver.add(flag_chars[0] == ord('r'))
state.solver.add(flag_chars[1] == ord('u'))
state.solver.add(flag_chars[2] == ord('n'))
state.solver.add(flag_chars[3] == ord('a'))
state.solver.add(flag_chars[4] == ord('2'))
state.solver.add(flag_chars[5] == ord('0'))
state.solver.add(flag_chars[6] == ord('2'))
state.solver.add(flag_chars[7] == ord('5'))
state.solver.add(flag_chars[8] == ord('{'))
state.solver.add(flag_chars[41] == ord('}'))

# Simulation manager 생성
simgr = proj.factory.simulation_manager(state)

# "Correct!" 문자열 주소 찾기
print("Searching for 'Correct!' address...")
# 실행 시작
simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1), avoid=lambda s: b"Wrong!" in s.posix.dumps(1))

if simgr.found:
    print("\n🎉 Solution found!")
    solution_state = simgr.found[0]
    solution = solution_state.solver.eval(flag, cast_to=bytes)
    print(f"FLAG: {solution.decode('utf-8', errors='ignore')}")
else:
    print("No solution found :(")
