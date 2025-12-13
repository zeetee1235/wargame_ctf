# Zeckendorf - Writeup

**Problem**: Zeckendorf representation and decoding

## 문제 분석

주어진 데이터:
- `FLAG_LEN = 74` (플래그 길이)
- `FIBONACCI = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233]` (12개의 피보나치 수)
- `NUMBERS` (111개의 숫자)

## Zeckendorf 정리란?

모든 양의 정수는 **연속되지 않는 피보나치 수의 합**으로 유일하게 표현될 수 있습니다.

**예시:**
- 12 = 8 + 3 + 1
- 50 = 34 + 13 + 3

## 풀이 과정

### Step 1: 데이터 구조 파악

```
FLAG_LEN = 74 (문자 개수)
FIBONACCI 개수 = 12 (최대 12비트)
NUMBERS 개수 = 111
111 * 8 비트 / 74 문자 = ~12 비트 per 문자
```

### Step 2: 비트 인코딩 이해

각 숫자(0-255)는 8비트로 표현됩니다. 이를 연결하여 하나의 비트스트림을 만듭니다.

```
NUMBERS = [162, 69, 36, ...]
           |10100010|01000101|00100100|...
```

### Step 3: Zeckendorf 디코딩

12개의 피보나치 수에 해당하는 12비트씩 묶어서:
- 비트 i가 1이면 FIBONACCI[i]를 포함
- 모든 포함된 피보나치 수를 더하면 ASCII 코드

```python
def decode_zeckendorf(bits_12, fibonacci):
    """12비트 -> ASCII 문자"""
    value = 0
    for i in range(12):
        if bits_12[i] == '1':
            value += fibonacci[i]
    return chr(value)
```

### Step 4: 완벽한 디코딩

```python
# 1. 모든 숫자를 비트스트림으로 변환
bitstream = ""
for num in NUMBERS:
    bitstream += bin(num)[2:].zfill(8)

# 2. 12비트씩 묶어서 디코딩 (FLAG_LEN = 74번)
FIBONACCI = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233]
decoded = []

for i in range(FLAG_LEN):
    start = i * 12
    end = start + 12
    bits_str = bitstream[start:end]
    
    # Zeckendorf 변환
    value = 0
    for j in range(len(FIBONACCI)):
        if j < len(bits_str) and int(bits_str[j]) == 1:
            value += FIBONACCI[j]
    
    decoded.append(chr(value))

flag = ''.join(decoded)
```

### Step 5: 플래그 획득

```
runa2025{a357118d0694a8bfb9df30487407a3fae9f968971bc3f6accc962a13038e21c3}
```

## 검증

- **길이**: 74문자 (FLAG_LEN과 일치)
- **형식**: `runa2025{...}` (올바른 플래그 형식)
- **내용**: 헥사데시마 해시로 보임 (SHA256?

)

## 핵심 아이디어

1. **Zeckendorf 표현**: 피보나치 수의 합으로 정수 표현
2. **비트마스크**: 각 비트가 특정 피보나치 수의 포함 여부를 나타냄
3. **그룹화**: FIBONACCI 개수(12)만큼의 비트 = 1 문자
4. **디코딩**: 비트마스크를 Zeckendorf로 변환하여 ASCII 코드 추출

## 추가 학습 포인트

- Zeckendorf 표현은 암호학과 데이터 압축에 활용됨
- 피보나치 수열의 성질과 응용
- 비트 조작과 인코딩 기법

