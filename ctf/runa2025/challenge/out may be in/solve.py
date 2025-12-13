#!/usr/bin/env python3
from pwn import *
import itertools

context.log_level = 'info'

HOST = 'rev.runa2025.kr'
PORT = 5008

p = remote(HOST, PORT)

# Receive initial messages
p.recvuntil(b'Good luck!\n')
p.recvuntil(b'----------------------------\n')

# Strategy: Find the answer using systematic guessing
# Then replay to get exactly 24 strikes, 0 balls, 1 out

def parse_result(data):
    """Parse Strike, Ball, Out from response"""
    try:
        if b'Strike:' in data:
            parts = data.split(b'Strike:')[1].split(b'Ball:')
            strikes = int(parts[0].strip().split()[0])
            
            parts = data.split(b'Ball:')[1].split(b'Out:')
            balls = int(parts[0].strip().split()[0])
            
            outs = int(data.split(b'Out:')[1].strip().split()[0])
            
            return strikes, balls, outs
    except:
        pass
    return None, None, None

# Phase 1: Find the answer by trying all positions
log.info("Phase 1: Finding the answer...")

# Use 0-9 to find all 5 digits
possible_digits = set(range(10))
answer = ['?'] * 5

# Try to find digits one by one
for try_num in range(1, 6):
    p.recvuntil(b'Enter 5-digit number> ')
    
    # For first 4 tries, systematically test digits
    if try_num <= 4:
        # Generate test number: try different combinations
        test_digits = list(range(try_num * 2 - 2, try_num * 2 + 3))[:5]
        # Ensure 5 unique digits
        test_num = ""
        used = set()
        for base in range(10):
            d = (base + try_num) % 10
            if d not in used:
                test_num += str(d)
                used.add(d)
            if len(test_num) == 5:
                break
        
        log.info(f"Try #{try_num}: Testing {test_num}")
        p.sendline(test_num.encode())
        
        data = p.recvuntil(b'Try #', timeout=3)
        if try_num < 5:
            p.unrecv(b'Try #')
        
        strikes, balls, outs = parse_result(data)
        log.info(f"  Result: {strikes}S {balls}B {outs}O")
    else:
        # Last try: use a common pattern
        test_num = "01234"
        log.info(f"Try #{try_num}: Testing {test_num}")
        p.sendline(test_num.encode())
        
        data = p.recv(timeout=3)
        strikes, balls, outs = parse_result(data)
        log.info(f"  Result: {strikes}S {balls}B {outs}O")

# Read final score
try:
    final = p.recv(timeout=2)
    log.info(f"Final output:\n{final.decode()}")
except:
    pass

p.interactive()
