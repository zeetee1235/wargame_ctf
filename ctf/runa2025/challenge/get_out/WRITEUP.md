# GET out of there! - Writeup

**Author**: 김민주  
**Server**: http://web.runa2025.kr:5001  
**Difficulty**: Easy (Web/Misc)

## 문제 분석

문제명: "GET out of there!"
- **"GET"**: HTTP GET 메서드 또는 응답 헤더에서 데이터를 "얻기"
- **"out of there"**: 응답 헤더에서 플래그를 "꺼내기"

## 풀이 과정

### Step 1: 초기 웹 서버 탐색

```bash
$ curl http://web.runa2025.kr:5001/
405 Method Not Allowed
```

GET 요청이 거부됩니다. 다른 HTTP 메서드를 시도해봅시다.

### Step 2: HTTP 메서드 테스트

```bash
$ curl -X HEAD http://web.runa2025.kr:5001/
200 OK

$ curl -X OPTIONS http://web.runa2025.kr:5001/
Allow: HEAD, GET, OPTIONS
```

HEAD 메서드는 200 OK를 반환하고, OPTIONS는 GET이 허용된다고 합니다. 하지만 GET은 405를 반환하는 모순이 발생합니다. 이는 파라미터가 필요하다는 신호입니다.

### Step 3: 파라미터 추가

문제명 "GET out of there"에서:
- **GET** = "out" 파라미터?
- **"out"** = 파라미터 값?

HEAD 메서드에 `?out` 파라미터를 추가하여 요청합니다:

```bash
$ curl -I http://web.runa2025.kr:5001/?out
HTTP/1.1 200 OK
X-Flag: runa2025{Welcome_to_RUNA_CTF_enjoyyy!!!!}
```

완벽합니다! X-Flag 헤더에 플래그가 있습니다.

## 플래그 획득

```
runa2025{Welcome_to_RUNA_CTF_enjoyyy!!!!}
```

## 풀이 코드

```python
import requests

base_url = "http://web.runa2025.kr:5001"

# HEAD 요청에 ?out 파라미터 추가
response = requests.head(base_url + "/", params={"out": ""}, timeout=5)

# X-Flag 헤더에서 플래그 추출
flag = response.headers.get('X-Flag')
print(f"Flag: {flag}")
```

## 핵심 개념

1. **HTTP 메서드 이해**
   - GET vs HEAD: GET은 응답 본문을, HEAD는 헤더만 반환
   - 웹 서버가 HTTP 메서드를 선택적으로 차단할 수 있음

2. **응답 헤더 분석**
   - 정보는 응답 본문뿐만 아니라 헤더에도 숨어있을 수 있음
   - `curl -I` 또는 `requests.head()`로 헤더만 추출 가능

3. **문제명 해석**
   - "GET out of there"는 단순한 문자 그대로의 의미
   - HTTP GET 메서드와 응답 헤더에서 플래그를 "꺼내는" 것

## 학습 포인트

- **웹 보안**: 숨겨진 정보가 응답 헤더에 있을 수 있음
- **HTTP 프로토콜**: 각 HTTP 메서드의 차이 이해
- **문제 해석**: 문제명 자체가 풀이 방법을 암시할 수 있음

