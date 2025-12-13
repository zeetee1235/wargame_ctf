# Tar Matryoshka - Writeup (진행 중)

**Problem**: "zip 마트로시카" - 중첩된 압축 파일 해제  
**Server**: nc misc.runa2025.kr 6008

## 문제 분석

"마트로시카" (Matryoshka) 인형처럼 중첩된 압축 파일을 계속 풀어야 하는 문제입니다.

## 진행 상황

### 시도 1: tar 파일 전송
```bash
tar czf flag.tar.gz flag.txt
```
**결과**: "It is not gzip" 응답

### 시도 2: 중첩된 tar.gz 전송 (Python)
```python
# depth별로 중첩된 tar.gz 생성
def create_nested_targz(depth):
    if depth == 0:
        return b'runa2025{...}'
    else:
        # 이전 결과를 tar.gz으로 감싸기
        inner = create_nested_targz(depth - 1)
        # gzip + tarfile로 압축
        return compressed_tar
```
**결과**: 동일하게 "It is not gzip"

### 시도 3: 수동으로 생성한 tar.gz 전송
```bash
tar czf level3.tar.gz level2.tar.gz
```
**결과**: "It is not gzip"

### 시도 4: 단순 gzip 압축 데이터
```python
compressed = gzip.compress(b"test")
sock.sendall(compressed)
```
**결과**: "It is not gzip"

## 문제점

모든 시도에서 "It is not gzip"이 반환됩니다:
- gzip 마직 바이트 `1f 8b`로 시작하는 모든 파일들이 거부됨
- tar 파일도 거부됨
- 단순 gzip 압축도 거부됨

## 추측

1. **서버의 gzip 검증이 매우 엄격**할 수 있음
   - 특정한 gzip 헤더나 메타데이터 필요?
   - 특정한 압축 플래그 필요?

2. **"It is not gzip"이 에러가 아니라 힌트**일 수 있음
   - 서버가 gzip을 원하지 않는다?
   - 다른 형식을 원하는 것?

3. **문제 설명에서 놓친 정보**
   - "zip 마트로시카"라고 명시했으므로 ZIP일 수도?
   - 하지만 ZIP을 보낼 때도 "It is not gzip" 응답

## 다음 시도

1. tar.gz 대신 ZIP 파일로만 구성한 마트로시카 재시도
2. 서버가 먼저 데이터를 보내는 경우 확인
3. 프로토콜 재분석 필요

## 관련 코드

```python
import socket
import gzip
import tarfile
import io
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("misc.runa2025.kr", 6008))

# "Input :" 프롬프트 수신
prompt = sock.recv(1024)

# 데이터 전송
sock.sendall(data)
sock.shutdown(socket.SHUT_WR)

time.sleep(0.5)

# 응답 수신
sock.settimeout(5)
response = b""
try:
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            break
        response += chunk
except socket.timeout:
    pass

print(f"Response: {response}")
sock.close()
```

## 상태

🔴 **진행 중** - 서버 동작 원리 파악 필요

