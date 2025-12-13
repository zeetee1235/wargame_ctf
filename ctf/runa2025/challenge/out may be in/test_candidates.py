#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

def parse_result(data):
    """Parse Strike, Ball, Out"""
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

# Known candidates after filtering
candidates = ['19537', '31957', '71395', '79531', '95137', '97135']

HOST = 'rev.runa2025.kr'
PORT = 5008

# Test each candidate
for candidate in candidates:
    log.info(f"\n=== Testing candidate: {candidate} ===")
    
    p = remote(HOST, PORT)
    p.recvuntil(b'Good luck!\n')
    p.recvuntil(b'----------------------------\n')
    
    # Test this candidate by guessing it multiple times
    test_results = []
    
    for try_num in range(1, 6):
        p.recvuntil(b'Enter 5-digit number> ')
        
        # Guess the candidate
        p.sendline(candidate.encode())
        
        if try_num < 5:
            data = p.recvuntil(b'Try #', timeout=3)
            p.unrecv(b'Try #')
        else:
            data = p.recv(timeout=3)
        
        strikes, balls, outs = parse_result(data)
        test_results.append((strikes, balls, outs))
        
        log.info(f"Try #{try_num}: {strikes}S {balls}B {outs}O")
        
        if strikes == 5:
            log.success(f"FOUND ANSWER: {candidate}")
            
            # Calculate score
            total_s = sum(r[0] for r in test_results)
            total_b = sum(r[1] for r in test_results)
            total_o = sum(r[2] for r in test_results)
            score = 10 * total_s + 5 * total_b - 3 * total_o
            
            log.success(f"Score with all correct: {score} (5 * 50 = 250)")
            
            final = p.recvall(timeout=2)
            log.info(f"Final output:\n{final.decode()}")
            
            p.close()
            
            # Now exploit with the answer
            log.info("\n" + "="*60)
            log.success(f"ANSWER FOUND: {candidate}")
            log.info("="*60)
            
            # Exit to use answer in next script
            import sys
            with open('/tmp/baseball_answer.txt', 'w') as f:
                f.write(candidate)
            sys.exit(0)
    
    p.close()
    
    # Check if we found it
    if any(r[0] == 5 for r in test_results):
        break
