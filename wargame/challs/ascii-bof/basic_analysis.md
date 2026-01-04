# ASCII-BOF 바이너리 기본 분석

## 🔍 바이너리 기본 정보

### 파일 정보
- **타입**: ELF 64-bit LSB pie executable
- **아키텍처**: x86-64
- **동적 링킁**: Yes
- **심볼 정보**: Not stripped (디버깅 정보 있음)

### 보안 설정 (checksec)
- ✅ **RELRO**: Full RELRO
- ❌ **Stack Canary**: No canary found ← **취약점!**
- ✅ **NX**: NX enabled (스택 실행 방지)
- ✅ **PIE**: PIE enabled (주소 랜덤화)
- ✅ **SHSTK**: Enabled
- ✅ **IBT**: Enabled

### 🎯 공격 가능성 분석
1. **Stack Canary 없음** → 버퍼 오버플로우 가능
2. **NX 활성화** → 스택에서 쉘코드 실행 불가
3. **PIE 활성화** → 함수 주소 예측 어려움
4. **Not stripped** → 함수명 확인 가능

## 다음 단계
- 함수들 확인 (objdump, nm)
- 소스코드 분석 (strings, disassemble)
- 취약한 함수 찾기
