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
        log.error(f"Parse error: {e}")
        log.error(f"Data: {data}")
    return None, None, None

HOST = 'rev.runa2025.kr'
PORT = 5008

p = remote(HOST, PORT)

# Receive initial messages
p.recvuntil(b'Good luck!\n')
p.recvuntil(b'----------------------------\n')

# Generate all possible 5-digit numbers with unique digits
all_candidates = [' '.join(map(str, perm)) for perm in itertools.permutations(range(10), 5)]
all_candidates = [''.join(c.split()) for c in all_candidates]  # Remove spaces

log.info(f"Total candidates: {len(all_candidates)}")

# Phase 1: Find the answer using information theory
guesses = []
results = []

for try_num in range(1, 6):
    p.recvuntil(b'Enter 5-digit number> ')
    
    if len(all_candidates) == 1:
        # Found the answer!
        guess = all_candidates[0]
        log.success(f"Found answer: {guess}")
    elif try_num == 1:
        # First guess: use a good starting guess
        guess = "01234"
    else:
        # Use first remaining candidate
        guess = all_candidates[0]
    
    log.info(f"Try #{try_num}: Guessing {guess} ({len(all_candidates)} candidates)")
    p.sendline(guess.encode())
    
    guesses.append(guess)
    
    # Receive result
    if try_num < 5:
        data = p.recvuntil(b'Try #', timeout=3)
        p.unrecv(b'Try #')
    else:
        data = p.recv(timeout=3)
    
    strikes, balls, outs = parse_result(data)
    if strikes is None:
        log.error("Failed to parse result!")
        log.error(f"Data: {data}")
        break
    
    results.append((strikes, balls, outs))
    log.info(f"  Result: {strikes}S {balls}B {outs}O")
    
    if strikes == 5:
        log.success("Got 5 strikes!")
        break
    
    # Filter candidates based on this result
    if try_num < 5:
        new_candidates = []
        for candidate in all_candidates:
            s, b = calculate_sb(guess, candidate)
            if s == strikes and b == balls:
                new_candidates.append(candidate)
        
        all_candidates = new_candidates
        log.info(f"  Remaining candidates: {len(all_candidates)}")
        
        if len(all_candidates) <= 5:
            log.info(f"  Candidates: {all_candidates[:5]}")

# Read final output
final = p.recvall(timeout=2)
log.info(f"Final output:\n{final.decode()}")

p.close()

# Calculate achieved score
total_strikes = sum(r[0] for r in results)
total_balls = sum(r[1] for r in results)
total_outs = sum(r[2] for r in results)
score = 10 * total_strikes + 5 * total_balls - 3 * total_outs

log.info(f"\nSummary:")
log.info(f"Total: {total_strikes}S {total_balls}B {total_outs}O")
log.info(f"Score: {score} (target: 237)")
log.info(f"Guesses: {guesses}")

if len(all_candidates) > 0:
    log.success(f"Answer found: {all_candidates[0] if len(all_candidates) == 1 else 'Multiple possibilities'}")
    if len(all_candidates) == 1:
        log.info(f"\n=== Strategy to get 237 points ===")
        log.info(f"Answer: {all_candidates[0]}")
        log.info(f"Need: 24S 0B 1O")
        log.info(f"Strategy: Guess correct answer 4 times, wrong once (4S 1O)")
