#!/usr/bin/env python3
"""
shototsu - 암호 충돌 문제
"""

import socket
import time

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('crypto.runa2025.kr', 6006))
    return s

def recv_all(s, timeout=5):
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

def main():
    print("[*] shototsu - Crypto Collision Problem")
    
    s = connect()
    
    # 전체 응답 받기
    response = recv_all(s)
    
    print("[+] Response received:")
    print(response.decode('utf-8', errors='ignore'))
    
    # 응답 분석
    lines = response.decode('utf-8', errors='ignore').split('\n')
    
    msg1_hex = None
    msg2_hex = None
    
    for i, line in enumerate(lines):
        if 'message1' in line.lower():
            # "message1 (hex): ..." 형식에서 hex 부분 추출
            if 'message1 (hex):' in line:
                msg1_hex = line.split('message1 (hex):')[1].strip()
            # 다음 줄에 계속될 수 있음
            if i+1 < len(lines) and not 'message2' in lines[i+1]:
                msg1_hex += lines[i+1].strip()
        
        if 'message2' in line.lower():
            if 'message2 (hex):' in line:
                msg2_hex = line.split('message2 (hex):')[1].strip()
            if i+1 < len(lines) and not 'False' in lines[i+1]:
                msg2_hex += lines[i+1].strip()
    
    print("\n[*] Extracted messages:")
    if msg1_hex:
        print(f"[+] Message 1 ({len(msg1_hex)} chars): {msg1_hex[:50]}...")
    if msg2_hex:
        print(f"[+] Message 2 ({len(msg2_hex)} chars): {msg2_hex[:50]}...")
    
    # 차이 분석
    if msg1_hex and msg2_hex:
        print("\n[*] Analyzing differences...")
        
        min_len = min(len(msg1_hex), len(msg2_hex))
        diff_positions = []
        
        for i in range(min_len):
            if msg1_hex[i] != msg2_hex[i]:
                diff_positions.append(i)
        
        print(f"[+] Different positions: {diff_positions}")
        
        for pos in diff_positions[:10]:  # 처음 10개만
            print(f"    Pos {pos}: '{msg1_hex[pos]}' vs '{msg2_hex[pos]}'")
    
    s.close()

if __name__ == '__main__':
    main()
