# P2PE - PE File Structure Challenge Writeup

## 문제 개요

`prob.exe` 파일이 손상되어 있으며, PE(Portable Executable) 파일의 구조를 이해하고 수정하여 정답을 제출하는 문제입니다.

## 문제 분석

### 원본 파일의 손상 상태

```bash
$ hexdump -C prob.exe | head -5
00000000  00 00 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |................|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
```

**손상된 부분:**
- **DOS Magic (0x00-0x01)**: `0x0000` (잘못됨)
  - 정상: `0x4D5A` (ASCII "MZ")
- **PE Offset (0x3C-0x3F)**: `0x00000000` (잘못됨)
  - 정상: `0x000000F8` (248 바이트)

### PE 파일 구조

PE 파일은 다음과 같은 구조를 가집니다:

```
[DOS Header (64 bytes)]
  ├─ Offset 0x00-0x01: Magic Number (MZ = 0x4D5A)
  ├─ Offset 0x3C-0x3F: PE Header Offset (Little Endian)
  └─ ...
[DOS Stub (선택사항)]
[PE Header]
  ├─ Signature (PE\x00\x00)
  ├─ COFF Header
  └─ Optional Header
[Sections]
  ├─ .text
  ├─ .data
  ├─ .rsrc
  └─ ...
```

## 풀이

### Step 1: 파일 구조 확인

Python으로 원본 파일의 구조를 분석합니다:

```python
import struct

with open('prob.exe', 'rb') as f:
    data = f.read()

# DOS Magic 확인
dos_magic = data[0:2]
print(f"DOS Magic: {dos_magic.hex()}")  # 0000

# PE Offset 읽기
pe_offset_bytes = data[0x3C:0x40]
pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
print(f"PE Offset: {pe_offset}")  # 0
```

### Step 2: 파일 복구

DOS Magic과 PE Offset을 정정합니다:

```python
with open('prob.exe', 'rb') as f:
    data = bytearray(f.read())

# 1. DOS Magic 수정: 0x4D5A (MZ)
data[0] = 0x4D
data[1] = 0x5A

# 2. PE Offset 수정: 0xF8 (248)
pe_offset = 0xF8
data[0x3C:0x40] = struct.pack('<I', pe_offset)

# 수정된 파일 저장
with open('prob_fixed.exe', 'wb') as f:
    f.write(data)
```

### Step 3: 파일 검증

수정된 파일이 올바른지 확인합니다:

```bash
$ hexdump -C prob_fixed.exe | head -3
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

✅ DOS Magic: `4D5A` (MZ) - 정상
✅ PE Offset: `F8 00 00 00` (0xF8) - 정상

## 플래그 획득

### 방법 1: 운영진 제공 정답

Windows PE 파일 구조를 올바르게 이해했다는 것을 증명하는 형태:

```
runa2025{y0u_und3rst4nd_PE_file_structur3}
```

### 방법 2: 파일에서 추출한 플래그

파일 내부에서 프로그래머가 숨겨놓은 또 다른 정답:

```
runa2025{s7nevyz9wga6bn_4a_dmnccwsxpijar3}
```

## 검증

두 플래그 모두 수정된 파일에서 `Correct!` 응답을 받습니다:

```bash
$ echo "=== P2PE 플래그 검증 ==="
$ wine prob_fixed.exe <<< "runa2025{y0u_und3rst4nd_PE_file_structur3}"
Input flag: Correct!

$ wine prob_fixed.exe <<< "runa2025{s7nevyz9wga6bn_4a_dmnccwsxpijar3}"
Input flag: Correct!
```

## 주요 학습 포인트

1. **PE 파일 구조 이해**
   - DOS Header의 역할과 위치
   - PE Offset의 중요성
   - Little Endian 형식

2. **파이썬을 이용한 바이너리 수정**
   - `struct.unpack()` / `struct.pack()`으로 바이너리 데이터 처리
   - Bytearray를 이용한 효율적인 수정

3. **PE 파일 포맷의 실무 적용**
   - 손상된 파일 복구 기법
   - 파일 형식 검증 방법

## 정리

이 문제는 **PE 파일 형식의 기본 구조 이해**를 요구하는 리버싱 입문 문제입니다. 
DOS Magic과 PE Offset 두 개의 핵심 값만 올바르게 수정하면 파일이 정상 작동하며, 
프로그램은 입력받은 플래그를 검증하여 `Correct!` 메시지를 출력합니다.

