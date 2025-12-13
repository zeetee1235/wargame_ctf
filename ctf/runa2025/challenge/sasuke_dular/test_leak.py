#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'

p = process('./sasuke_dular')

def register(day, start, end, name):
    p.sendlineafter(b'>', b'1')  # Register
    p.sendlineafter(b'day', str(day).encode())
    p.sendlineafter(b'time', str(start).encode())
    p.sendlineafter(b'time', str(end).encode())
    p.sendlineafter(b'name', name)

def show(day):
    p.sendlineafter(b'>', b'2')  # Show
    p.sendlineafter(b'day', str(day).encode())
    data = p.recv(timeout=2)
    return data

# Register at the last slot (day 6, hour 18)
# day=6, hour=18 → index = 6*11 + (18-8) = 66+10 = 76
register(6, 17, 18, b'AAAAAAAA')

# Show day 6
result = show(6)
print("Result:")
print(result)

p.interactive()
