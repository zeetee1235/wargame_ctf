#!/usr/bin/env python3
from pwn import *

binary = './sasuke_dular'
elf = ELF(binary)
libc = ELF('./libc.so.6')

context.log_level = 'debug'

target = process(binary)

# Interact to understand the program flow
target.interactive()
