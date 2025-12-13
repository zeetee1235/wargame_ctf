#!/usr/bin/env python3
"""
Assem..ble? 문제 솔버

이 문제는 입력 문자열을 복잡한 비트 연산과 테이블 룩업으로 검증합니다.
알고리즘:
1. 각 문자를 비트 셔플
2. 길이와 XOR 및 ADD
3. 위치 기반 테이블 룩업 후 XOR
4. 모든 결과를 OR하여 최종 r14가 0이면 성공

로컬 바이너리 분석 결과: "b" (길이 1)가 정답
"""

import struct
import sys

def extract_tables_from_binary(binary_path):
    """바이너리에서 테이블 추출"""
    with open(binary_path, 'rb') as f:
        binary = f.read()
    
    # Extract pointer table at 0x402114
    pointers = []
    for i in range(16):
        offset = 0x2114 + i * 8
        ptr = struct.unpack('<Q', binary[offset:offset+8])[0]
        pointers.append(ptr)
    
    # Extract actual tables
    tables = []
    for ptr in pointers:
        table_offset = ptr - 0x400000
        table_data = binary[table_offset:table_offset+16]
        tables.append(table_data)
    
    return tables

def bit_shuffle(val):
    """비트 재배열 함수"""
    r8 = 0
    if val & 0x01: r8 |= 0x20
    if val & 0x02: r8 |= 0x40
    if val & 0x04: r8 |= 0x80
    if val & 0x08: r8 |= 0x01
    if val & 0x10: r8 |= 0x02
    if val & 0x20: r8 |= 0x04
    if val & 0x40: r8 |= 0x08
    if val & 0x80: r8 |= 0x10
    return r8

def check_string(s, tables):
    """문자열이 조건을 만족하는지 체크"""
    r13 = len(s) & 0xff
    r14 = 0
    
    for r12, char in enumerate(s):
        # Step 1: Bit shuffle
        r8 = bit_shuffle(char)
        
        # Step 2: XOR and ADD with length
        r8 = (r8 ^ r13) & 0xff
        r8 = (r8 + r13) & 0xff
        
        # Step 3: Table lookup
        high_nibble = (r12 >> 4) & 0xf
        table_idx = (high_nibble * 2) + 1
        low_nibble = r12 & 0xf
        
        table_byte = tables[table_idx][low_nibble]
        
        # Step 4: XOR with table
        r8 ^= table_byte
        
        # Step 5: OR into r14
        r14 |= r8
    
    return r14 == 0

def find_solution(tables, max_length=64):
    """주어진 테이블로 솔루션 찾기"""
    def find_char_at_pos(pos, target_length):
        r13 = target_length & 0xff
        high_nibble = (pos >> 4) & 0xf
        table_idx = (high_nibble * 2) + 1
        low_nibble = pos & 0xf
        table_byte = tables[table_idx][low_nibble]
        
        # Reverse calculation
        r8_after_xor_add = table_byte
        r8_after_xor = (r8_after_xor_add - r13) & 0xff
        target_shuffle = r8_after_xor ^ r13
        
        # Find character
        for c in range(256):
            if bit_shuffle(c) == target_shuffle:
                return c
        return None
    
    # Try different lengths
    for test_len in range(1, max_length + 1):
        result = []
        for pos in range(test_len):
            char = find_char_at_pos(pos, test_len)
            if char is not None:
                result.append(char)
            else:
                break
        
        if len(result) == test_len:
            result_bytes = bytes(result)
            if check_string(result_bytes, tables):
                return result_bytes
    
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 solver.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    print(f"[*] Analyzing binary: {binary_path}")
    tables = extract_tables_from_binary(binary_path)
    print(f"[+] Extracted {len(tables)} lookup tables")
    
    print("[*] Finding solution...")
    solution = find_solution(tables)
    
    if solution:
        print(f"\n[+] FOUND SOLUTION!")
        print(f"[+] Length: {len(solution)}")
        print(f"[+] Hex: {solution.hex()}")
        print(f"[+] Bytes: {solution}")
        
        try:
            decoded = solution.decode('ascii')
            print(f"[+] ASCII: {decoded}")
        except:
            try:
                decoded = solution.decode('latin-1')
                print(f"[+] Latin-1: {decoded}")
            except:
                print("[!] Cannot decode as text")
        
        # Verify
        if check_string(solution, tables):
            print(f"[✓] Verification: PASS")
        else:
            print(f"[✗] Verification: FAIL")
    else:
        print("[-] No solution found")
