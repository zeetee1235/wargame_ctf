#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
# context.log_level = 'debug'

HOST = 'pwn.runa2025.kr'
PORT = 7004

def register(p, day, start, end, name):
    p.recvuntil(b'>', timeout=2)
    p.sendline(b'1')
    p.recvuntil(b':', timeout=2)
    p.sendline(str(day).encode())
    p.recvuntil(b':', timeout=2)
    p.sendline(str(start).encode())
    p.recvuntil(b':', timeout=2)
    p.sendline(str(end).encode())
    p.recvuntil(b':', timeout=2)
    p.send(name)

def show(p, day):
    p.recvuntil(b'>', timeout=2)
    p.sendline(b'2')
    p.recvuntil(b':', timeout=2)
    p.sendline(str(day).encode())

def clear_day(p, day):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b':', str(day).encode())

def connect():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process('./sasuke_dular')

def main():
    p = connect()
    
    # Test: Just try a simple register and show
    log.info("Testing normal operation...")
    register(p, 0, 8, 10, b'TESTTEST')
    show(p, 0)
    
    # Try to see what we get
    data = p.recv(timeout=2)
    log.info(f"Received: {data}")
    
    p.interactive()

if __name__ == '__main__':
    main()
