# LSB Oracle Attack - "d" Problem

## Problem Summary
복호화 시 secret key `d`의 일부 LSB (Least Significant Bits)가 강제로 0이 되는 하드웨어 오류가 발생했습니다.
공격자는 어떤 LSB를 0으로 만들지 선택할 수 있었고, 결과적인 복호화 output들의 로그를 수집했습니다.

## Given Data
- `n`: RSA modulus (1024-bit)
- `c`: Ciphertext
- `shift[]`: 각 oracle에서 LSBs가 0이 되는 위치들 (160개)
- `challenge.txt`: 160개의 oracle 결과값들 = `c^(d & mask[i]) mod n`

## Key Challenge
Each oracle gives us: `oracle[i] = c^(d & mask[i]) mod n`
where `mask[i]` has bits [shift[i], 1023] set to 1 and bits [0, shift[i]-1] set to 0.

This is equivalent to a **discrete logarithm problem** for each oracle.

## Analysis Done

### 1. Bit-by-bit Reconstruction
Attempted to reconstruct d bit by bit using oracle constraints.
**Result**: Failed - most bits had contradicting constraints

### 2. Oracle Ratio Analysis
Computed ratios between consecutive oracles:
- `oracle[i] / oracle[i+1] = c^((d & mask[i]) - (d & mask[i+1]))`
- This isolates bits in specific ranges

Found some 3-4 bit ranges that could be brute forced but most were too large.

### 3. Small Bit Range Brute Force
For consecutive shifts differing by ≤ 12 bits, attempted brute force DLP.
**Result**: Most ranges yielded no matches or all zeros

### 4. Direct Mask Value Hypothesis
Tested if challenge.txt contained actual `(d & mask)` values instead of `c^(d & mask)`.
**Result**: Did not match when reconstructing d

### 5. Verification Against prob.py
Compared expected values from prob.py with challenge.txt.
**Result**: Values don't match - indicates challenge.txt was generated from real (unknown) flag, not "runa2025{fake_flag}"

## The Core Problem
Without either:
1. **n's factorization** (to compute φ(n) and analyze order of c)
2. **Additional information** about d (bounds, format constraints, etc.)
3. **Different attack vector** (e.g., if c has special structure)

We cannot solve the discrete logarithm problem to recover d from the oracle values.

## Potential Solution Paths

### Path 1: Factor n
If n could be factored as n = p*q, we could:
- Compute φ(n) = (p-1)(q-1)
- Find order of c modulo n
- Use Pohlig-Hellman attack on small-order factors
- Potentially recover d bits

### Path 2: Exploit Special Properties
If d has known structure (e.g., small, has known prefix "runa2025", etc.):
- Could use CRT with φ(n) if available
- Could exploit algebraic relationships

### Path 3: Meet-in-the-Middle
If d is sufficiently small:
- Split d into two halves
- Build lookup table for c^(d_high) mod n for all possible d_high
- For each d_low, compute c^(d_low) and check if ratio appears in table

### Path 4: Lattice-Based Methods
- BKZ/LLL algorithms if we can formulate as lattice problem
- Coppersmith's method if d is sufficiently small (< n^0.29)

## Current Status
**BLOCKED** - Requires either:
- Additional hint/information about d
- Means to factor n or compute φ(n)
- Different problem interpretation

## Files
- `prob.py`: Test case generator (uses fake_flag)
- `challenge.txt`: 160 oracle outputs (generated from real flag)
- `solver*.py`: Various attempted solution approaches

## References
- LSB Oracle Attack (Manger's attack related)
- Discrete Logarithm Problem
- Pohlig-Hellman Attack
- Index Calculus
