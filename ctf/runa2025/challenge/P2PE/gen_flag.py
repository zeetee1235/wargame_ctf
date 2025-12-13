# 우리가 고친 3개 부분:
# 1. offset 0x00: 00 00 -> 4D 5A (MZ magic)
# 2. offset 0x3C: 00 00 00 00 -> F8 00 00 00 (e_lfanew)  
# 3. offset 0x15C: 00 00 00 00 -> 0c fa 0b c7 (checksum)

checksum = 0x0cfa0bc7

# 가능한 플래그 형식들
flags = [
    # Hex 값들 사용
    f"runa2025{{4d5a_f8_0cfa0bc7}}",  # 언더스코어
    f"runa2025{{4d5af80cfa0bc7}}",    # 연속
    f"runa2025{{MZ_F8_0CFA0BC7}}",   # 대문자
    f"runa2025{{mz_f8_0cfa0bc7}}",   # 소문자
    
    # 설명적 형식
    f"runa2025{{MZ_e_lfanew_F8_checksum_0CFA0BC7}}",
    f"runa2025{{dos_sig_MZ_pe_offset_F8_checksum}}",
    
    # 10진수
    f"runa2025{{4d5a_248_{checksum}}}",
    
    # MD5 or hash
    import hashlib
    hashlib.md5(b"MZ\xF8" + checksum.to_bytes(4, 'little')).hexdigest(),
]

for i, flag in enumerate(flags[:-1]):  # MD5 제외
    print(f"{i+1}. {flag} (len={len(flag)})")

# MD5 플래그
md5_hash = hashlib.md5(b"MZ\xF8" + checksum.to_bytes(4, 'little')).hexdigest()
print(f"8. runa2025{{{md5_hash}}} (len={len('runa2025{'+md5_hash+'}')})")

# 역순이나 다른 조합도 시도
print(f"\n9. runa2025{{{checksum:08x}_f8_4d5a}} (len={len(f'runa2025{{{checksum:08x}_f8_4d5a}}')})")

