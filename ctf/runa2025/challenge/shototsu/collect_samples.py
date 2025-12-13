#!/usr/bin/env python3
"""
shototsu - 더 많은 샘플 수집
"""

import socket
import time

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('crypto.runa2025.kr', 6006))
    return s

def recv_response(s, timeout=2):
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

def send_input(s, msg):
    """서버에 메시지 전송"""
    s.send((msg + '\n').encode())
    time.sleep(0.1)

def main():
    print("[*] shototsu - Sample Collection")
    
    s = connect()
    
    # 초기 응답 읽기
    initial = recv_response(s)
    print("[+] Initial response:")
    print(initial.decode('utf-8', errors='ignore')[:300])
    
    print("\n[*] Sending test inputs...")
    
    # 테스트: "flag"라고 보내보기
    send_input(s, "flag")
    resp = recv_response(s)
    
    if b"runa" in resp or b"flag" in resp:
        print("[!] Got response mentioning flag!")
        print(resp.decode('utf-8', errors='ignore')[:500])
    
    # 다른 커맨드 시도
    send_input(s, "help")
    resp = recv_response(s)
    if resp:
        print("\n[+] Help response:")
        print(resp.decode('utf-8', errors='ignore')[:500])
    
    s.close()
    
    # 새로운 연결
    print("\n[*] Starting fresh connection...")
    s = connect()
    recv_response(s)  # 초기 응답 버림
    
    # 더 간단한 입력들로 시도
    test_inputs = [
        "runa2025{test}",
        "A",
        "AA",
        "AAA",
        "AAAA",
        "test",
        "",
    ]
    
    for test_input in test_inputs:
        try:
            send_input(s, test_input)
            resp = recv_response(s)
            
            if resp and len(resp) > 20:
                print(f"\n[+] Input: '{test_input}'")
                print(f"    Response ({len(resp)} bytes): {resp[:100].hex()}...")
        except:
            break
    
    s.close()

if __name__ == '__main__':
    main()
