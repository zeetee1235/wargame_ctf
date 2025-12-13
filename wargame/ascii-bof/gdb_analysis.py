#!/usr/bin/env python3

"""
GDB를 사용한 실제 메모리 분석
"""

from pwn import *
import subprocess

def analyze_with_gdb():
    """GDB로 상세 분석"""
    print("[+] GDB 상세 분석")
    print("=" * 50)
    
    # GDB 스크립트 생성
    gdb_script = """
set pagination off
file ./main
b *main
run
info registers
x/20i $rip
p/x $rsp
p/x $rbp
print "=== main 함수 분석 ==="
disassemble main
print "=== 0x1297 함수 분석 ==="
disassemble 0x1297
print "=== 0x1339 주소 확인 ==="
x/20i 0x1339
print "=== 스택 상태 ==="
x/10gx $rsp
quit
"""
    
    with open('gdb_script.txt', 'w') as f:
        f.write(gdb_script)
    
    print("GDB 스크립트 실행 중...")
    result = subprocess.run(['gdb', '-batch', '-x', 'gdb_script.txt'], 
                          capture_output=True, text=True)
    
    print("GDB 출력:")
    print(result.stdout)
    if result.stderr:
        print("GDB 에러:")
        print(result.stderr)

def test_overflow_with_gdb():
    """오버플로우 지점을 GDB로 확인"""
    print("\n[+] 오버플로우 지점 GDB 확인")
    print("=" * 50)
    
    # 32바이트 입력으로 크래시 지점 분석
    gdb_script = """
set pagination off
file ./main
b *0x1297
run
c
# 32바이트 입력 준비
set $input = "AAAAAAAAAAAAAAAABBBBBBBBCCCCCCCC"
# 스택 상태 확인
x/10gx $rsp
x/10gx $rbp-0x20
info registers
c
info registers
quit
"""
    
    with open('gdb_overflow.txt', 'w') as f:
        f.write(gdb_script)
    
    print("오버플로우 GDB 스크립트 실행...")

def find_flag_function():
    """플래그 함수 정확한 위치 찾기"""
    print("\n[+] 플래그 함수 정확한 위치 찾기")
    print("=" * 50)
    
    # objdump에서 확인한 주소들 재검증
    addresses = [0x1339, 0x1297, 0x1229]
    
    for addr in addresses:
        print(f"\n주소 0x{addr:x} 분석:")
        result = subprocess.run(['objdump', '-d', './main', '-M', 'intel'], 
                              capture_output=True, text=True)
        
        lines = result.stdout.split('\n')
        found = False
        for i, line in enumerate(lines):
            if f'{addr:x}:' in line:
                found = True
                print(f"발견: {line}")
                # 다음 몇 줄도 출력
                for j in range(1, 6):
                    if i+j < len(lines):
                        print(f"    {lines[i+j]}")
                break
        
        if not found:
            print(f"주소 0x{addr:x}에서 코드를 찾을 수 없음")

def simple_gdb_test():
    """간단한 GDB 테스트"""
    print("\n[+] 간단한 GDB 테스트")
    print("=" * 50)
    
    # 가장 기본적인 정보부터
    commands = [
        ('info functions', '함수 목록'),
        ('disassemble main', 'main 함수'),
        ('x/20i 0x1297', '0x1297 주소'),
        ('x/20i 0x1339', '0x1339 주소'),
    ]
    
    for cmd, desc in commands:
        print(f"\n{desc}:")
        result = subprocess.run(['gdb', '-batch', '-ex', cmd, './main'], 
                              capture_output=True, text=True)
        print(result.stdout)

if __name__ == "__main__":
    print("🔍 GDB 메모리 분석")
    print("=" * 60)
    
    # 1. 기본 GDB 분석
    simple_gdb_test()
    
    # 2. 플래그 함수 찾기
    find_flag_function()
    
    # 3. 상세 분석
    # analyze_with_gdb()
    
    print("\n🎯 다음 단계:")
    print("- 실제 익스플로잇 코드 작성")
    print("- 로컬에서 플래그 함수 호출 시도")
    print("- 서버와 로컬 차이점 분석")
