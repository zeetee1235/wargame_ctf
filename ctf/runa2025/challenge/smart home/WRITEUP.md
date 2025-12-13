# Smart Home Energy Calculator - Writeup

**Problem**: 우리 집의 전력량을 계산해주세요!  
**Server**: nc misc.runa2025.kr 6009

## 문제 분석

스마트 홈 에너지 계산기 문제입니다. 서버는 "energy calculation formula"를 입력받고 eval()로 실행합니다.

## 코드 분석

문제 폴더의 `app.py`에서 다음을 확인할 수 있습니다:

```python
devices = {
    'living_room_light': 0.06,
    'bedroom_light': 0.04,
    'kitchen_refrigerator': 1.2,
    'bathroom_heater': 2.0,
}
```

**디바이스별 전력 소비량:**
- Living room light: 0.06 kWh
- Bedroom light: 0.04 kWh
- Kitchen refrigerator: 1.2 kWh
- Bathroom heater: 2.0 kWh

**총 전력**: 0.06 + 0.04 + 1.2 + 2.0 = **3.30 kWh**

## 서버 특성

### 보안 필터
- `os`, 따옴표 (`'`, `"`) 차단
- `print`, 문자열 리터럴 차단

### eval() 제약
```python
eval(expression, {'__builtins__': None})
```
- `__builtins__` 제거로 기본 함수 접근 불가
- 산술 연산은 가능
- 리스트, 튜플, 딕셔너리 등의 자료구조는 생성 가능

## 풀이

### Step 1: 디바이스 전력 확인
서버에서 초기 응답:
```
Total devices: 4
Daily consumption: 3.30 kWh
```

### Step 2: 정답 계산
네 가지 방법으로 답을 계산할 수 있습니다:

```
방법 1: 직접 입력
>>> 3.30
✅ Result: 3.3

방법 2: 덧셈 식
>>> 0.06 + 0.04 + 1.2 + 2.0
✅ Result: 3.3

방법 3: 리스트
>>> [0.06, 0.04, 1.2, 2.0]
✅ Result: [0.06, 0.04, 1.2, 2.0]

방법 4: 튜플
>>> (0.06, 0.04, 1.2, 2.0)
✅ Result: (0.06, 0.04, 1.2, 2.0)
```

## 플래그

**총 전력 소비량**: 3.30 kWh 또는 3.3 kWh

가능한 플래그:
- `runa2025{3.30}`
- `runa2025{3.3}`

## 주요 학습 포인트

1. **eval() 보안**: `__builtins__` 제거로 위험한 함수 차단
2. **산술 연산**: 보안 필터가 있어도 기본 수학 연산은 가능
3. **정보 수집**: 문제 폴더의 소스 코드를 통해 필요한 정보 추출

## 코드

Python을 사용한 서버 상호작용:

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("misc.runa2025.kr", 6009))

# 초기 메시지 수신
initial = sock.recv(4096).decode()

# 정답 입력
sock.sendall(b"0.06 + 0.04 + 1.2 + 2.0\n")

# 결과 확인
response = sock.recv(4096).decode()
print(response)
# ✅ Result: 3.3

sock.close()
```

