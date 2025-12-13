#!/usr/bin/env python3
"""
shototsu - Final solution
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

def main():
    print("[*] shototsu - Submitting collision")
    
    s = connect()
    
    # Initial response (showing example collision)
    initial = recv_all(s)
    print("[+] Initial response received")
    
    # Our collision: t1 + 0x00 and t2 + 0x00
    m1_hex = "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b900"
    m2_hex = "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b900"
    
    print(f"\n[+] Submitting m1:")
    print(f"    {m1_hex}")
    
    s.send((m1_hex + '\n').encode())
    time.sleep(0.1)
    
    resp1 = recv_all(s)
    print(f"[+] Response: {resp1.decode('utf-8', errors='ignore')[:100]}")
    
    print(f"\n[+] Submitting m2:")
    print(f"    {m2_hex}")
    
    s.send((m2_hex + '\n').encode())
    time.sleep(0.1)
    
    resp2 = recv_all(s)
    print(f"[+] Response: {resp2.decode('utf-8', errors='ignore')[:200]}")
    
    s.close()
    
    print("\n[*] Done!")

if __name__ == '__main__':
    main()
