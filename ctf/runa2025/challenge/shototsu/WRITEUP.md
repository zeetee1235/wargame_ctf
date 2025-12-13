# shototsu - MD4 Collision Challenge Writeup

## 문제 설명
쉬운 난이도의 암호화 문제로, MD4 해시 함수의 충돌(collision)을 찾아야 합니다.

- **점수**: 488점
- **난이도**: Newbie (쉬움)
- **서버**: crypto.runa2025.kr:6006
- **목표**: 서버가 제시한 충돌과 다른 새로운 MD4 충돌을 찾아서 flag 획득

## 문제 분석

### 초기 상황
서버는 다음과 같은 정보를 제공합니다:
- 기본 MD4 해시 함수 구현
- 두 개의 메시지 `t1`, `t2`가 동일한 해시값을 가짐 (`encrypt(t1) == encrypt(t2)`)
- 이와 **다른** 충돌을 찾아야 flag를 획득

### MD4 구조 분석
```
- 3개의 Round 처리 (Round 1, Round 2, Round 3)
- Round별 상수: C2=0x5A827999, C3=0x6ED9EBA1
- 32비트 덧셈과 비트 회전(bit rotation) 사용
- 최종 출력: 16바이트 (128비트)
```

### 핵심 발견 1: t1과 t2의 관계
서버에서 제시한 충돌을 분석하면:
- t1과 t2는 매우 유사함
- 차이점: **단 3바이트만 다름** (위치 7, 11, 50)
  - 위치 7: 0x80 vs 0x8A
  - 위치 11: 0x00 vs 0x90
  - 위치 50: 0x00 vs 0x01

이는 MD4의 약점을 보여줍니다 - 작은 변화가 해시에 영향을 주지 않습니다.

### 핵심 발견 2: 메시지 길이 확장을 통한 충돌 탐지
초기 시도:
- 무작위 2바이트 flip: 백만 번 시도했으나 실패
- 이유: 완전히 새로운 충돌을 찾기는 매우 어려움

**돌파구**: MD4의 패딩 메커니즘 활용
- MD4는 64바이트 블록 단위로 처리
- 원본 t1, t2는 각각 64바이트로 정렬됨
- **이들에 동일한 바이트를 추가하면 충돌이 유지됨!**

실험:
```
encrypt(t1) == encrypt(t2)  ✓
encrypt(t1 + 0x00) == encrypt(t2 + 0x00)  ✓ (새로운 충돌!)
```

### 왜 이것이 작동하는가?
MD4의 패딩 구조:
1. 메시지 길이가 정보에 포함됨
2. 길이가 다르더라도 동일한 해시 상태에서 시작
3. 추가된 데이터가 동일하면 최종 해시도 동일
4. 이는 MD4가 근본적으로 안전하지 않다는 증거

## 풀이 과정

### Step 1: 문제 이해
```python
# 서버에서 제공하는 기본 충돌
t1 = bytes.fromhex("839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b")
t2 = bytes.fromhex("839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b")

# 확인: encrypt(t1) == encrypt(t2)
```

### Step 2: 충돌 확장
```python
from prob import encrypt

# 원본 충돌
print(encrypt(t1) == encrypt(t2))  # True

# 새로운 충돌 생성
m1 = t1 + b'\x00'
m2 = t2 + b'\x00'

print(encrypt(m1) == encrypt(m2))  # True (새로운 충돌!)
print(m1 != m2)  # True
print(m1 != t1)  # True
print(m1 != t2)  # True
```

### Step 3: 서버에 제출
```python
import socket

def submit_collision(m1, m2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('crypto.runa2025.kr', 6006))
    
    # 메시지를 16진수 문자열로 인코딩
    m1_hex = m1.hex()
    m2_hex = m2.hex()
    
    # 초기 응답 수신
    s.recv(1024)
    
    # m1 제출
    s.send((m1_hex + '\n').encode())
    resp1 = s.recv(1024)
    
    # m2 제출
    s.send((m2_hex + '\n').encode())
    resp2 = s.recv(16384)
    
    s.close()
    
    return resp2.decode('utf-8', errors='ignore')

# 실행
m1 = t1 + b'\x00'
m2 = t2 + b'\x00'
flag = submit_collision(m1, m2)
print(flag)
```

## 최종 결과

### 제출된 충돌
```
m1 = 839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b900
m2 = 839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b900
```

### 획득한 Flag
```
runa2025{md4_collision_is_really_danger_crypt0system_and_so_many_pair}
```

## 교훈

1. **MD4는 암호학적으로 깨짐**: 작은 변화만으로 충돌 메시지 생성 가능
2. **"쉬운" 문제의 의미**: 완전히 새로운 공격을 찾기보다, 주어진 정보를 활용하는 것이 핵심
3. **메시지 확장의 활용**: 해시 함수의 특성을 이용하면 문제가 간단해질 수 있음
4. **서버의 힌트**: 기본 충돌을 보여줌으로써 접근 방향을 제시

## 참고 자료

- MD4는 RFC 1320에서 정의되었으나 1997년에 충돌이 발견됨
- 현재는 보안 목적으로 절대 사용하면 안 됨
- SHA-256 등의 현대적 해시 함수 사용 권장
