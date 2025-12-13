#!/usr/bin/env python3
from pwn import *
import itertools
import random

context.log_level = 'info'

def calculate_sb(guess, answer):
    """Calculate strikes and balls"""
    strikes = sum(1 for i in range(5) if guess[i] == answer[i])
    balls = sum(1 for g in guess if g in answer) - strikes
    return strikes, balls

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

def find_best_guess(candidates):
    """Find guess that maximizes information gain"""
    if len(candidates) <= 10:
        return candidates[0]
    
    # Sample some guesses to test
    sample_size = min(200, len(candidates))
    sample = random.sample(candidates, sample_size)
    
    best_guess = sample[0]
    best_score = 0
    
    for guess in sample[:20]:  # Test first 20
        # Count how many different (s,b) outcomes this guess produces
        outcomes = {}
        for candidate in sample:
            s, b = calculate_sb(guess, candidate)
            key = (s, b)
            outcomes[key] = outcomes.get(key, 0) + 1
        
        # Best guess minimizes maximum bucket size
        score = len(outcomes) - max(outcomes.values()) / sample_size * 10
        if score > best_score:
            best_score = score
            best_guess = guess
    
    return best_guess

HOST = 'rev.runa2025.kr'
PORT = 5008

p = remote(HOST, PORT)
p.recvuntil(b'Good luck!\n')
p.recvuntil(b'----------------------------\n')

all_candidates = [''.join(map(str, perm)) for perm in itertools.permutations(range(10), 5)]
log.info(f"Total candidates: {len(all_candidates)}")

guesses = []
results = []

# Better starting guesses based on information theory
good_starts = ["01234", "56789", "02468", "13579", "24680"]

for try_num in range(1, 6):
    p.recvuntil(b'Enter 5-digit number> ')
    
    if len(all_candidates) == 1:
        guess = all_candidates[0]
        log.success(f"Found answer: {guess}")
    elif try_num <= len(good_starts) and len(all_candidates) > 100:
        guess = good_starts[try_num - 1]
    else:
        guess = find_best_guess(all_candidates)
    
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
        log.error("Parse failed!")
        break
    
    results.append((strikes, balls, outs))
    log.info(f"  → {strikes}S {balls}B {outs}O")
    
    if strikes == 5:
        log.success(f"ANSWER: {guess}")
        break
    
    # Filter
    if try_num < 5:
        new_candidates = []
        for candidate in all_candidates:
            s, b = calculate_sb(guess, candidate)
            if s == strikes and b == balls:
                new_candidates.append(candidate)
        
        all_candidates = new_candidates
        log.info(f"  Remaining: {len(all_candidates)}")
        
        if len(all_candidates) <= 20:
            log.info(f"  Top candidates: {all_candidates[:20]}")

final = p.recvall(timeout=2)
log.info(f"\nFinal:\n{final.decode()}")

p.close()

total_s = sum(r[0] for r in results)
total_b = sum(r[1] for r in results)
total_o = sum(r[2] for r in results)
score = 10 * total_s + 5 * total_b - 3 * total_o

log.info(f"\n=== Summary ===")
log.info(f"Total: {total_s}S {total_b}B {total_o}O = {score} points")
log.info(f"Guesses: {guesses}")

if len(all_candidates) <= 20:
    log.info(f"Final candidates: {all_candidates}")
