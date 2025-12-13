# ASCII-BOF 완전 분석 보고서

## 🎯 프로그램 구조 분석

### 함수 구조
1. **main 함수** (0x1229): 메인 진입점
2. **취약한 함수** (0x1297): main+0x6e에서 호출되는 함수
3. **플래그 함수** (0x1339): 플래그를 출력하는 함수

### 📋 main 함수 분석 (0x1229~0x1296)

```assembly
1229: endbr64                    # Intel CET 
122d: push rbp                   # 스택 프레임 설정
122e: mov rbp,rsp

# setvbuf 설정 (stdin, stdout)
1231-124a: setvbuf(stdin, ...)   
124f-1268: setvbuf(stdout, ...)  

126d: lea rax,[rip+0xd94]        # 첫 번째 메시지 출력
1274: mov rdi,rax
1277: call puts@plt

127c: call 1297                  # 🎯 취약한 함수 호출!

1281: lea rax,[rip+0xd89]        # "You are hacker!" 메시지
1288: mov rdi,rax  
128b: call puts@plt

1290: mov eax,0x0                # return 0
1295: pop rbp
1296: ret
```

### 🔥 취약한 함수 분석 (0x1297~0x1338)

```assembly
1297: endbr64
129b: push rbp                   # 스택 프레임 설정
129c: mov rbp,rsp
129f: sub rsp,0x10              # 🎯 16바이트 지역 변수 할당

# 버퍼 초기화 (16바이트)
12a3: mov QWORD PTR [rbp-0x10],0x0  # 8바이트 초기화
12ab: mov QWORD PTR [rbp-0x8],0x0   # 8바이트 초기화

# read() 호출 - 🚨 버퍼 오버플로우 지점!
12b3: lea rax,[rbp-0x10]        # 버퍼 주소 (16바이트)
12b7: mov edx,0x20              # 🚨 32바이트 읽기! (16바이트 버퍼에)
12bc: mov rsi,rax               # 버퍼 주소
12bf: mov edi,0x0               # stdin
12c4: call read@plt             # read(0, buffer, 32)

12c9: mov [num],eax             # 읽은 바이트 수 저장

# ASCII 체크 루프
12cf: mov DWORD PTR [i],0x0     # i = 0
12d9: jmp 1325                  # 루프 조건 체크로 점프

# 루프 내부 (12db~1333)
12db: mov eax,[i]               # i 로드
12e1: cdqe                      # 64비트로 확장
12e3: movzx eax,BYTE PTR [rbp+rax*1-0x10]  # buffer[i] 로드

# ASCII 체크: 0x20 < byte < 0x7f
12e8: cmp al,0x20               # byte <= 0x20 체크
12ea: jle 12fd                  # 실패시 에러 메시지

12ec: mov eax,[i]               # i 다시 로드  
12f2: cdqe
12f4: movzx eax,BYTE PTR [rbp+rax*1-0x10]  # buffer[i] 로드
12f9: cmp al,0x7f               # byte >= 0x7f 체크
12fb: jne 1316                  # 성공시 다음 바이트로

# ASCII 체크 실패
12fd: lea rax,[rip+0xd23]       # 에러 메시지
1304: mov rdi,rax
1307: call puts@plt
130c: mov edi,0x1
1311: call exit@plt             # 프로그램 종료

# ASCII 체크 성공
1316: add eax,0x1               # i++
131f: mov [i],eax

# 루프 조건
1325: mov edx,[i]               # i 로드
132b: mov eax,[num]             # 읽은 바이트 수 로드
1331: cmp edx,eax               # i < num 체크
1333: jl 12db                   # 루프 계속

1335: nop                       # 루프 종료
1336: nop
1337: leave                     # 🎯 스택 프레임 해제
1338: ret                       # 🚨 리턴 주소로 점프!
```

### 🏆 플래그 함수 분석 (0x1339~0x13e2)

```assembly
1339: endbr64
133d: push rbp
133e: mov rbp,rsp

# 파일 열기
1341: lea rax,[rip+0xcef]       # "r" 모드
1348: mov rsi,rax
134b: lea rax,[rip+0xce8]       # "flag.txt" 파일명
1352: mov rdi,rax
1355: call fopen@plt

135a: mov [fp],rax              # 파일 포인터 저장
1361: mov rax,[fp]
1368: test rax,rax              # 파일 열기 성공 체크
136b: jne 1386

# 파일 열기 실패
136d: lea rax,[rip+0xcd4]       # 에러 메시지
1374: mov rdi,rax
1377: call puts@plt
137c: mov edi,0x1
1381: call exit@plt

# 플래그 읽기
1386: mov rax,[fp]
138d: lea rdx,[flag]            # 🎯 flag 전역 변수 (0x4060)
1394: lea rcx,[rip+0xcdb]       # "%s" 포맷
139b: mov rsi,rcx
139e: mov rdi,rax
13a1: mov eax,0x0
13a6: call fscanf@plt           # fscanf(fp, "%s", flag)

13ab: mov rax,[fp]
13b2: mov rdi,rax
13b5: call fclose@plt

# 플래그 출력! 🎉
13ba: lea rax,[flag]            # flag 전역 변수
13c1: mov rsi,rax
13c4: lea rax,[rip+0xcae]       # "%s\n" 포맷
13cb: mov rdi,rax
13ce: mov eax,0x0
13d3: call printf@plt           # printf("%s\n", flag)

13d8: mov edi,0x0
13dd: call exit@plt
```

## 🎯 핵심 취약점 분석

### 버퍼 오버플로우
- **버퍼 크기**: 16바이트 (rbp-0x10 ~ rbp-0x1)
- **읽기 크기**: 32바이트
- **오버플로우**: 16바이트 초과 가능

### 스택 구조
```
높은 주소
+-----------------+
|   return addr   |  <- rbp+8 (리턴 주소)
+-----------------+
|   saved rbp     |  <- rbp (저장된 RBP)
+-----------------+
|                 |  <- rbp-8
|   16-byte       |
|   buffer        |  <- rbp-16 (버퍼 시작)
+-----------------+
낮은 주소
```

### 공격 벡터
1. **32바이트 입력** → 16바이트 버퍼 + 8바이트 RBP + 8바이트 리턴 주소 덮어쓰기
2. **ASCII 체크 우회**: 모든 바이트가 0x20 < byte < 0x7f 조건 만족
3. **목표**: 리턴 주소를 플래그 함수(0x1339)로 변경

## 🚀 공격 계획
1. 16바이트 패딩 + 8바이트 RBP + 8바이트 플래그 함수 주소
2. 모든 바이트는 ASCII 범위 내여야 함
3. PIE로 인해 실제 주소는 베이스 + 0x1339
