---
title: "[Rev] safe not safe"
description: Writing about the "safe not safe" of BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Rev]
toc: true
comments: false
---

# safe not safe (BITS CTF 2026)
<img width="667" height="643" alt="image" src="https://github.com/user-attachments/assets/52208de0-a5c7-4336-ab4d-0a0adfc8b9b2" />

---

- Name : safe not safe
- Category : Rev
- Description : I forgot the password to my smart safe :( Luckily, I was able to dump the firmware.
- Difficulty : ★★☆☆☆

---

# TL;DR

이 문제는 겉으로는 `/dev/urandom`을 써서 안전해 보이지만,   
실제로는 `challenge`와 `response`를 만들 때 **같은 랜덤값을 XOR로 재사용**해서 서로 상쇄된다.    
그래서 `/dev/urandom` 값을 몰라도, **시간 기반 PRNG(`srand(time)` + `rand`) 흐름만 재현하면 response를 계산할 수 있다.**   

결과적으로 비밀번호 리셋을 성공시키고 `/dev/vda`에서 읽은 플래그가 출력된다.  

**Flag:** `BITSCTF{7h15_41n7_53cur3_571ll_n07_p47ch1ng_17}`

---

# Overview

이 문제는 ARM 환경(QEMU)에서 동작하는 `lock_app` 바이너리를 리버싱하는 문제다.    
서비스에 접속하면 바로 바이너리가 뜨는 게 아니라 **셸(`/ $`)** 이 먼저 나오고,   
사용자가 직접 `/challenge/lock_app`를 실행해야 한다.

프로그램 메뉴는 대략 아래와 같다.

1. Enter access code  
2. Reset password  
3. Exit

1번(접근 코드 입력)은 실제로 구현이 안 되어 있고(낚시),  
**진짜 포인트는 2번 Reset password 기능**이다.

Reset password를 성공하면 프로그램이 `/dev/vda`를 읽어서 **플래그를 출력**한다.

---

# Solution

## 1) Recon

### 1-1. 제공 파일 확인
압축 파일 안에는 대략 이런 것들이 있었다.

- `zImage` (ARM 리눅스 커널)
- `run.sh` (QEMU 실행 스크립트)
- `Dockerfile`
- `flag.txt` (더미 플래그)

`run.sh`를 보면 실제 플래그는 `/dev/vda` 블록 디바이스로 연결되는 구조였다.  
즉, **프로그램이 `/dev/vda`를 읽게 만들면 플래그 획득** 가능.

---

### 1-2. zImage / initramfs 분석
커널 내부 initramfs를 꺼내보면 `/challenge/lock_app` 바이너리가 있었다.

`/init` 스크립트 흐름은 대략:

- 시스템 세팅
- `/challenge/lock_app` setuid root 설정
- 셸 실행 (`/bin/sh`)
- 사용자에게 `/challenge/lock_app` 실행 안내

즉, 네트워크 연결 후 바로 메뉴가 안 뜨고 **셸이 먼저 뜨는 구조**였다.  
이 점 때문에 자동화 스크립트에서 처음 timeout이 났다.

---

### 1-3. 바이너리 동작 확인
문자열에서 확인되는 힌트

- `PASSWORD RESET VERIFICATION`
- `Your challenge code is: %06u`
- `Response code:`
- `PASSWORD RESET SUCCESSFUL`
- `Here's a gift: %s`
- `/dev/vda`

이걸 보면:
- 2번 메뉴에서 challenge code를 보여주고
- 사용자가 response code를 넣으면 검증 후
- 성공 시 `/dev/vda` 내용을 gift로 출력한다는 걸 알 수 있었다.

---

## 2) Root cause

핵심 버그는 **challenge/response 생성 방식**이다.

프로그램은 랜덤처럼 보이게 만들려고 `/dev/urandom`도 사용하고, `rand()`도 섞는다.  
하지만 최종 식이 잘못 설계되어 있어서 **랜덤값이 상쇄된다.**

### 프로그램 내부 개념
프로그램은 대략 이런 값을 만든다:

- `u` = `/dev/urandom`에서 읽은 값
- `x`, `y` = `rand()` 기반 + 테이블 치환으로 만든 값 (시간 seed로 재현 가능)

그리고:

- `challenge = u ^ F(x, y)`
- `response  = u ^ G(x, y)`

여기서 `^`는 XOR.

### 왜 취약한가?
사용자는 `challenge`를 볼 수 있고, `response`는 맞춰야 한다.  
그런데 위 식을 보면 둘 다 **같은 `u`를 XOR로 재사용**한다.

따라서:

`response = challenge ^ F(x, y) ^ G(x, y)`

즉, **`u`가 사라진다(상쇄됨)**.

이 말은 곧:
- `/dev/urandom` 값을 몰라도 됨
- `x, y`만 맞추면 response 계산 가능

---

## 3) Exploit

---

### 3-1. response 계산
Reset password에서 얻는 값:

- `init_time` (프로그램이 출력)
- `challenge code` (프로그램이 출력)

그리고 `reset_time`은 보통 `init_time` 직후이므로:

- `reset_time = init_time + delta`
- `delta`를 `0 ~ 20` 정도 브루트포스

하면서 각 후보 response를 계산했다.

정답이 맞으면:

- `PASSWORD RESET SUCCESSFUL`
- `Here's a gift: BITSCTF{...}`

가 출력된다.

---

## 4) Why it works

이 문제가 풀린 이유를 아주 쉽게 말하면:

### 비유
개발자가 “비밀 숫자(u)”를 숨기려고 challenge/response 둘 다에 넣었는데,    
둘 다 **같은 방식(XOR)** 으로 넣어서, 계산하다 보면 **비밀 숫자가 서로 지워져 버린 것**이다.  

즉, 랜덤을 넣긴 넣었는데 **설계를 잘못해서 랜덤이 보호 역할을 못 함**.  

---

### 기술적으로 정리
성공 조건은 response를 맞추는 것인데, response가 실제로는:

- `challenge`
- 시간 기반 PRNG 결과 (`rand`)
- 프로그램 내부의 고정 연산

으로만 결정된다.

그리고 시간 seed는 프로그램이 직접 출력하므로,  
남는 불확실성은 `reset_time`의 몇 초 차이뿐 → 작은 범위 브루트포스로 해결 가능.

그래서 이 문제는 **“암호학적 안전성 문제”라기보다 “잘못된 랜덤/PRNG/XOR 설계 문제”**에 가깝다.

---

# Solver

아래는 풀이에 필요한 핵심 아이디어를 정리한 solver 요약이다.

### 핵심 로직
1. 원격 접속
2. 셸 프롬프트(`/ $`) 대기
3. `/challenge/lock_app` 실행
4. `The current time is: <init_time>` 파싱
5. 메뉴에서 `2` 입력
6. `Your challenge code is: <challenge>` 파싱
7. `delta` 범위 브루트포스 (`init_time + delta`)
8. 각 delta에 대해 response 계산
9. 정답 입력 → 성공 시 플래그 출력

### 계산식 요약
- `challenge = u ^ ((x*31337 + y) % 1000000)`
- `response  = u ^ ((x ^ y) % 1000000)`

따라서

- `response = challenge ^ ((x*31337 + y) % 1000000) ^ ((x ^ y) % 1000000)`

여기서 `u`는 사라진다.

---
<img width="700" height="420" alt="image" src="https://github.com/user-attachments/assets/6845ca19-0cdc-4fe5-b5c1-e8d25bfcf5ec" />
---
