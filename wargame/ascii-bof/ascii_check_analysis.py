#!/usr/bin/env python3

"""
ASCII-BOF ASCII 체크 로직 정확한 분석
"""

from pwn import *

def test_ascii_failure():
    """ASCII 체크 실패 케이스 찾기"""
    print("[+] ASCII 체크 실패 케이스 찾기")
    print("=" * 50)
    
    binary_path = './main'
    
    # 확실히 실패할 바이트들 테스트
    fail_bytes = [0x00, 0x01, 0x0a, 0x0d, 0x1f, 0x80, 0xff]
    
    for byte_val in fail_bytes:
        print(f"\n테스트: 0x{byte_val:02x}")
        try:
            p = process(binary_path)
            payload = bytes([byte_val]) + b"A" * 15
            p.sendline(payload)
            output = p.recvall(timeout=2)
            
            if b"You are not a hacker!" in output:
                print(f"🚨 ASCII 체크 실패! 바이트: 0x{byte_val:02x}")
            else:
                print(f"✅ 통과: {output}")
            
            p.close()
        except Exception as e:
            print(f"오류: {e}")

def test_different_positions():
    """다른 위치에서 ASCII 체크"""
    print("\n[+] 다른 위치에서 ASCII 체크")
    print("=" * 50)
    
    binary_path = './main'
    
    # 다른 위치에 문제 바이트 배치
    positions = [0, 5, 10, 15]
    problem_byte = 0x00
    
    for pos in positions:
        print(f"\n위치 {pos}에 0x{problem_byte:02x} 배치")
        try:
            p = process(binary_path)
            payload = b"A" * pos + bytes([problem_byte]) + b"A" * (15 - pos)
            p.sendline(payload)
            output = p.recvall(timeout=2)
            print(f"결과: {output}")
            p.close()
        except Exception as e:
            print(f"오류: {e}")

def understand_ascii_check_logic():
    """ASCII 체크 로직 이해"""
    print("\n[+] ASCII 체크 로직 재분석")
    print("=" * 50)
    
    print("objdump 분석 결과 재검토:")
    print("12e8: cmp al,0x20      # byte <= 0x20 체크")
    print("12ea: jle 12fd         # 실패시 에러")
    print("12f9: cmp al,0x7f      # byte >= 0x7f 체크") 
    print("12fb: jne 1316         # 성공시 계속")
    print()
    print("🤔 분석:")
    print("- byte <= 0x20 이면 실패")
    print("- byte >= 0x7f 이면 실패")
    print("- 따라서 0x20 < byte < 0x7f 만 허용")
    print()
    print("하지만 테스트에서는 모든 바이트가 통과...")
    print("🎯 가능한 이유:")
    print("1. 로컬 바이너리와 서버 바이너리가 다름")
    print("2. ASCII 체크가 읽은 바이트 수만큼만 체크")
    print("3. NULL 바이트로 인한 문자열 종료")

def test_null_byte_impact():
    """NULL 바이트의 영향 테스트"""
    print("\n[+] NULL 바이트 영향 테스트")
    print("=" * 50)
    
    binary_path = './main'
    
    test_cases = [
        (b"AAAA\x00BBBB", "중간에 NULL"),
        (b"\x00AAAAAAAA", "시작에 NULL"),
        (b"AAAAAAA\x00", "끝에 NULL"),
        (b"AAAAAAAA", "NULL 없음"),
    ]
    
    for payload, desc in test_cases:
        # 16바이트로 패딩
        if len(payload) < 16:
            payload += b"C" * (16 - len(payload))
        else:
            payload = payload[:16]
            
        print(f"\n테스트: {desc}")
        print(f"페이로드: {payload}")
        try:
            p = process(binary_path)
            p.sendline(payload)
            output = p.recvall(timeout=2)
            print(f"결과: {output}")
            p.close()
        except Exception as e:
            print(f"오류: {e}")

if __name__ == "__main__":
    print("🔍 ASCII-BOF ASCII 체크 로직 정확한 분석")
    print("=" * 60)
    
    # 1. ASCII 실패 케이스 찾기
    test_ascii_failure()
    
    # 2. 다른 위치에서 테스트
    test_different_positions()
    
    # 3. 로직 이해
    understand_ascii_check_logic()
    
    # 4. NULL 바이트 영향
    test_null_byte_impact()
    
    print("\n🎯 결론:")
    print("로컬 테스트를 통해 ASCII 체크 로직을 정확히 파악하고")
    print("실제 서버에서의 동작과 비교 분석 필요")
