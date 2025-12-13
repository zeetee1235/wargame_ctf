#!/usr/bin/env python3
from pwn import *
import itertools

context.log_level = 'info'

def calculate_sb(guess, answer):
    """Calculate strikes and balls for a guess against an answer"""
    strikes = sum(1 for i in range(5) if guess[i] == answer[i])
    balls = sum(1 for g in guess if g in answer) - strikes
    return strikes, balls

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
    except Exception as e:
        pass
    return None, None, None

HOST = 'rev.runa2025.kr'
PORT = 5008

# Run multiple times to find answer
for attempt in range(3):
    log.info(f"\n=== Attempt {attempt + 1} ===")
    
    p = remote(HOST, PORT)
    p.recvuntil(b'Good luck!\n')
    p.recvuntil(b'----------------------------\n')

    all_candidates = [''.join(map(str, perm)) for perm in itertools.permutations(range(10), 5)]
    
    guesses = []
    results = []
    
    for try_num in range(1, 6):
        p.recvuntil(b'Enter 5-digit number> ')
        
        if len(all_candidates) == 1:
            guess = all_candidates[0]
            log.success(f"Answer: {guess} - Guessing it!")
        elif try_num == 1:
            guess = "01234"
        elif try_num == 2:
            guess = "56789"
        else:
            guess = all_candidates[0]
        
        log.info(f"Try #{try_num}: {guess} ({len(all_candidates)} candidates)")
        p.sendline(guess.encode())
        guesses.append(guess)
        
        if try_num < 5:
            data = p.recvuntil(b'Try #', timeout=3)
            p.unrecv(b'Try #')
        else:
            data = p.recv(timeout=3)
        
        strikes, balls, outs = parse_result(data)
        if strikes is None:
            break
        
        results.append((strikes, balls, outs))
        log.info(f"  → {strikes}S {balls}B {outs}O")
        
        if strikes == 5:
            log.success(f"FOUND IT: {guess}")
            
            # Now we know the answer, let's calculate how to get 237 points
            answer = guess
            log.info("\n=== Planning for 237 points ===")
            log.info(f"Answer: {answer}")
            log.info(f"Target: 24S 0B 1O = 237 points")
            log.info(f"Strategy: Guess correct 4 times (20S), wrong once (4S 1O)")
            log.info(f"  Try 1-4: {answer} → 5S each = 20S total")
            log.info(f"  Try 5: {answer[1:] + answer[0]} (rotate) → 4S 1O")
            
            # Save answer for next attempt
            with open('/tmp/answer.txt', 'w') as f:
                f.write(answer)
            
            p.close()
            exit(0)
        
        # Filter candidates
        if try_num < 5:
            new_candidates = []
            for candidate in all_candidates:
                s, b = calculate_sb(guess, candidate)
                if s == strikes and b == balls:
                    new_candidates.append(candidate)
            
            all_candidates = new_candidates
            
            if len(all_candidates) <= 10:
                log.info(f"  Candidates: {all_candidates}")
    
    final = p.recvall(timeout=1)
    p.close()
    
    total_s = sum(r[0] for r in results)
    total_b = sum(r[1] for r in results)
    total_o = sum(r[2] for r in results)
    score = 10 * total_s + 5 * total_b - 3 * total_o
    log.info(f"Score: {score}, Total: {total_s}S {total_b}B {total_o}O")
    
    if len(all_candidates) <= 5:
        log.info(f"Remaining candidates: {all_candidates}")
