# Redeem Code - Writeup

**Problem**: Ticket Redeemer (CRT mode)  
**Endpoints**: 
- GET /sample_user
- POST /redeem {"token":"..."}

## 문제 분석

JWT+Bcrypt 기반의 토큰 검증 시스템입니다.

## 토큰 구조

```
base64url(payload) . base64url(salt) . base64url(signature)
```

### 페이로드 예시
```json
{
    "role": "user",
    "email": "user@example.com",
    "iat": 1234567890,
    "exp": 1234571490
}
```

## 서명 검증 로직

```python
def sign_payload(payload_bytes, salt):
    msg = payload_bytes + b'.' + ADMIN_SECRET
    return bcrypt.hashpw(msg, salt)

def verify_token(token):
    p_b64, s_b64, h_b64 = token.split('.')
    payload_bytes = b64u_dec(p_b64)
    salt = b64u_dec(s_b64)
    sig = b64u_dec(h_b64)
    
    ok = bcrypt.hashpw(payload_bytes + b'.' + ADMIN_SECRET, salt) == sig
    # ...
```

## 취약점

### 핵심 문제: ADMIN_SECRET이 빈 문자열!

서버의 `ADMIN_SECRET`을 보안 토큰이 아니라 **빈 문자열 `b''`**로 설정했습니다.

### 공격 방법

1. **sample_user 토큰에서 salt 추출**
   ```python
   r = requests.get("/sample_user")
   token = r.json()["token"]
   p_b64, s_b64, h_b64 = token.split('.')
   salt = b64u_dec(s_b64)
   ```

2. **VIP 페이로드 생성**
   ```python
   vip_payload = {
       "email": "user@example.com",
       "exp": int(time.time()) + 3600,
       "iat": int(time.time()),
       "role": "vip"  # 핵심: role을 vip로 변경
   }
   ```

3. **서명 생성 (알려진 ADMIN_SECRET과 salt 사용)**
   ```python
   ADMIN_SECRET = b''  # 빈 문자열!
   
   payload_bytes = json.dumps(vip_payload, ...).encode()
   msg = payload_bytes + b'.' + ADMIN_SECRET
   sig = bcrypt.hashpw(msg, salt)
   ```

4. **VIP 토큰 조립**
   ```python
   vip_token = '.'.join([
       b64u_enc(payload_bytes),
       b64u_enc(salt),
       b64u_enc(sig)
   ])
   ```

5. **플래그 획득**
   ```python
   r = requests.post("/redeem", json={"token": vip_token})
   capsule = b64u_dec(r.json()["capsule"])
   
   # 복호화
   key = hashlib.sha256(vip_token.encode()).digest()
   flag = xor_repeat(capsule, key).decode()
   ```

## 플래그

```
runa2025{bcrypt_truncation_ftw}
```

## 핵심 학습 포인트

1. **ADMIN_SECRET의 중요성**
   - 보안 토큰 생성에 빈 문자열 사용은 치명적
   - 서버의 비밀값은 충분한 엔트로피를 가져야 함

2. **Bcrypt의 특성**
   - 같은 salt로 같은 메시지를 해싱하면 같은 결과
   - 하지만 salt는 공개되므로 ADMIN_SECRET이 중요

3. **Token Forging**
   - 클라이언트가 토큰 구조를 알고 있으면 위험
   - 서명 검증의 보안은 ADMIN_SECRET의 강도에 의존

## 완전한 Exploit 코드

```python
import requests
import json
import base64
import bcrypt
import hashlib
import time

BASE_URL = "http://crypto.runa2025.kr:6001"
ADMIN_SECRET = b''

def b64u_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def b64u_dec(s):
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# sample_user에서 salt 추출
r = requests.get(f"{BASE_URL}/sample_user")
token = r.json()["token"]
p_b64, s_b64, h_b64 = token.split('.')
salt = b64u_dec(s_b64)

# VIP 토큰 생성
now = int(time.time())
vip_payload = {
    "email": "user@example.com",
    "exp": now + 3600,
    "iat": now,
    "role": "vip"
}

payload_bytes = json.dumps(vip_payload, separators=(',', ':'), sort_keys=True).encode()
msg = payload_bytes + b'.' + ADMIN_SECRET
sig = bcrypt.hashpw(msg, salt)

vip_token = '.'.join([b64u_enc(payload_bytes), b64u_enc(salt), b64u_enc(sig)])

# 플래그 획득
r = requests.post(f"{BASE_URL}/redeem", json={"token": vip_token})
capsule = b64u_dec(r.json()["capsule"])

key = hashlib.sha256(vip_token.encode()).digest()
def xor_repeat(data, key):
    k = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(d ^ k[i] for i, d in enumerate(data))

flag = xor_repeat(capsule, key).decode()
print(f"Flag: {flag}")
```

