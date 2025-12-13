#!/usr/bin/env python3

# Goal: Find combination to get score = 237
# Score = 10*strike + 5*ball - 3*out
# Total = strike + ball + out = 25 (5 tries * 5 digits each)

target = 237
total_digits = 25

for strikes in range(0, 26):
    for balls in range(0, 26 - strikes):
        outs = total_digits - strikes - balls
        score = 10 * strikes + 5 * balls - 3 * outs
        
        if score == target:
            print(f"Strike: {strikes}, Ball: {balls}, Out: {outs}, Score: {score}")
            
            # Check if this is achievable in 5 tries
            # Each try has 5 digits, max 5 strikes per try
            if strikes <= 25 and balls <= 25 and outs >= 0:
                print(f"  → Feasible!")
                # Example distribution
                print(f"  → Example: Try to get ~{strikes/5:.1f} strikes, ~{balls/5:.1f} balls, ~{outs/5:.1f} outs per try")
