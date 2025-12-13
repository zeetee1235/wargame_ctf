#!/usr/bin/env python3
"""
shototsu - 안전하지 않은 암호 시스템 분석
"""

import socket
import time

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('crypto.runa2025.kr', 6006))
    return s

def recv_all(s, timeout=3):
    s.settimeout(timeout)
    result = b""
    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            result += data
    except socket.timeout:
        pass
    return result

def send_msg(s, data):
    s.send(data)
    time.sleep(0.1)

def main():
    print("[*] shototsu - Unsafe Crypto System")
    
    # 분석 결과:
    # 두 메시지가 다르지만 같은 해시를 가짐
    # 차이는 3개 바이트뿐:
    # - Byte 7: 0x80 차이
    # - Byte 11: 0x90 차이  
    # - Byte 50: 0x01 차이
    
    msg1_hex = "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9"
    msg2_hex = "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9"
    
    msg1_bytes = bytes.fromhex(msg1_hex)
    msg2_bytes = bytes.fromhex(msg2_hex)
    
    print("[+] Message 1:")
    print(f"    {msg1_hex}")
    print(f"    Bytes: {msg1_bytes.hex()}")
    
    print("\n[+] Message 2:")
    print(f"    {msg2_hex}")
    print(f"    Bytes: {msg2_bytes.hex()}")
    
    print("\n[+] Analysis:")
    print(f"    Both produce same hash = collision!")
    print(f"    Only 3 bytes differ")
    
    # 이제 플래그를 얻으려면:
    # 1. 서버가 우리에게 메시지를 보냄
    # 2. 우리는 이를 변조하여 같은 해시를 가지게 할 수 있음
    # 3. 또는 역으로 플래그를 계산할 수 있음
    
    # 패턴 분석: 이것은 XOR 기반 해시인가?
    # 3바이트 차이만 있으므로 간단한 구조일 것
    
    print("\n[*] Attempting to understand the hash algorithm...")
    
    # 서버에 접속하여 다른 메시지도 요청해보기
    s = connect()
    response = recv_all(s)
    
    response_text = response.decode('utf-8', errors='ignore')
    print("\n[+] Server response:")
    print(response_text[:500])
    
    # 문제: "Can you find?" = 플래그를 찾으라는 의미
    # 우리가 할 수 있는 것:
    # 1. 메시지 자체를 변조하기
    # 2. 특정 메시지가 특정 해시 값을 가지도록 하기
    # 3. 역함수 구현하기
    
    print("\n[*] Strategy:")
    print("    The hash function has only 3 bytes difference")
    print("    Likely a simple XOR-based or linear function")
    print("    We need to find the plaintext that hashes to...")
    
    # 플래그 후보 시도
    # runa2025{...} 형식일 것
    
    s.close()
    
    print("\n[*] Trying to find flag format...")
    
    # 만약 hash(msg1) == hash(msg2)이고
    # 이 둘이 다른 64바이트 값이라면,
    # 역함수를 찾을 수 있을까?
    
    # 더 간단한 접근: brute force로 가능한 플래그들을 시도
    flag_prefix = b"runa2025{"
    
    # 하지만 먼저 서버 구조를 더 이해해야 함
    # 혹은 더 많은 collision 예제를 받아야 함
    
    print("[*] Need more information from server to solve")

if __name__ == '__main__':
    main()
