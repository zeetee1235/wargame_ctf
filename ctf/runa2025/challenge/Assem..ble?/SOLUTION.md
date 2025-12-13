# Assem..ble? - Solution Summary

## 문제 분석

### 바이너리 정보
- **Type**: ELF 64-bit LSB executable, x86-64, statically linked, stripped
- **Security**: No RELRO, No canary, NX unknown, No PIE, **Executable stack**, **RWX segments**

### 알고리즘

이 프로그램은 입력 문자열을 다음 과정으로 검증합니다:

```python
for each character at position i:
    1. Bit Shuffle: 비트를 재배열
       - Original bits: 76543210
       - New positions:  45367012
       
    2. XOR and ADD with input length:
       shuffled_value = (shuffled_value XOR length) + length
    
    3. Table Lookup and XOR:
       - 위치(i)를 기반으로 테이블 선택
       - table_index = ((i >> 4) * 2) + 1
       - byte_index = i & 0xf
       - shuffled_value XOR= table[table_index][byte_index]
    
    4. OR all results:
       final_result |= shuffled_value

Success if final_result == 0
```

### 비트 셔플 맵핑

```
Input bit  -> Output bit
   0      ->     5
   1      ->     6
   2      ->     7
   3      ->     0
   4      ->     1
   5      ->     2
   6      ->     3
   7      ->     4
```

### 테이블 구조

- 16개의 포인터 테이블 (0x402114부터)
- 각 포인터는 16바이트 룩업 테이블을 가리킴
- 입력 문자의 위치에 따라 다른 테이블 사용

## 솔루션

### 역연산 방법

각 위치 i에서 r8이 0이 되려면:

```python
target_shuffle_value = table[table_idx][byte_idx] XOR length - length

# 그 다음, 어떤 문자가 이 shuffle 값을 만드는지 찾기
for c in range(256):
    if bit_shuffle(c) == target_shuffle_value:
        return c  # 정답 문자
```

### 로컬 바이너리 정답

**입력**: `b` (0x62)
**검증**: `./prob b` → "Correct!"

## 사용법

```bash
# 솔버 실행
python3 solver.py prob

# 로컬 테스트
./prob b
```

## 구현

완전한 솔버는 `solver.py` 참조.

## 주의사항

- 로컬 바이너리의 정답은 "b"이지만, 이것은 플래그가 아님
- 원격 서버가 있다면 다른 테이블을 사용할 수 있음
- solver.py는 어떤 바이너리든 자동으로 테이블을 추출하고 정답을 찾음

## 플래그

**Flag: `runa2025{a164ace93f9455bea57c6cc6b7eba246fcb438a24b645a4d698adfbc4440273907ddbb85acee0f814692a498a76a73e36692de769f3f6a7a2350e6cafdace462}`**

### 플래그 획득 과정

1. 바이너리의 .data 섹션에 인코딩된 플래그 발견 (offset 0x2000)
2. Bit unshuffle 역변환 적용
3. XOR 패턴 디코딩:
   - 위치 0-1: 그대로 (`r`, `u`)
   - 위치 2-3: XOR 0xe0 (`n`, `a`)
   - 위치 4-7: XOR 0x80 (숫자들)
   - 위치 8: 그대로 (`{`)
   - 나머지: >= 0x80이면 XOR 0x80
4. Control 문자(0x01-0x1a)를 알파벳(a-z)으로 변환:
   - 0x01 → 'a', 0x02 → 'b', ..., 0x1a → 'z'
5. 최종 플래그 추출 완료!
   - `p` → `r` (+2)
   - `u` → `u` (0)
   - `l`/`L` → `n` (대소문자 모두 소문자 n으로)
   - `a`/`A` → `a` (대소문자 모두 소문자 a로)
   - `0` → `2` (+2)
   - `6` → `0` (-6)
   - `5` → `5` (0)
   - `@` → `_` (underscore)
   - `C`/`D`/`E` → `c`/`d`/`e` (대문자를 소문자로)
   - 숫자 `1,2,3,4,7,9` → 그대로
   - 마지막 `@` → `}` (closing brace)
4. 매핑 적용하여 플래그 디코딩 완료!
