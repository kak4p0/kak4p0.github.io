---
title: "[Pwn] Midnight Relay"
description: Writing about the "Midnight Relay" of BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Pwn]
toc: true
comments: false
---

# Midnight Relay (BITS CTF 2026)
---
- Name : Midnight Relay
- Category : Pwn
- Description : A fallback relay was brought online during a midnight outage. 
- Difficulty : ★☆☆☆☆
---

## TL;DR

`midnight_relay`는 **힙 기반 UAF + 내부 트레일러(out-of-bounds) read/write**를 이용해,   
최종적으로 `fire()`가 호출하는 **함수 포인터를 `system`으로 바꿔** 쉘을 얻는 문제다.

핵심 체인:

- `observe/tune`가 `size + 0x20`까지 허용 → **트레일러 leak/overwrite**
- `shred`가 `free()` 후 포인터 초기화 안 함 → **UAF**
- 트레일러에서 **cookie/PIE leak**
- UAF로 **libc leak**
- 위조 트레일러 + `sync` 토큰 계산 후 `fire` → `system("/bin/sh")`

최종 플래그:
- `BITSCTF{m1dn1ght_r3l4y_m00nb3ll_st4t3_p1v0t}`

---

## Overview

문제는 커스텀 바이너리 프로토콜(`op/key/len/payload`)을 사용하고, 내부적으로 `slot[]`에 shard를 저장한다.

주요 명령:

- `forge` : shard 생성
- `tune` : shard에 쓰기
- `observe` : shard 읽기
- `shred` : shard 해제
- `sync` : 토큰 검증 후 arm
- `fire` : 내부 트레일러를 기반으로 함수 호출

보호기법은 켜져 있음 (PIE/NX/RELRO/Canary).  
따라서 정석은 **메모리 취약점 + 로직 악용**이다.

---

## Solution

### 1) Recon

#### ① 프로토콜 분석
패킷 형식:
- `op (1B)`
- `key (1B)` : checksum
- `len (2B, little-endian)`
- `payload`

`key`는 payload와 epoch 기반으로 계산됨.  
epoch는 성공한 패킷마다 갱신됨 → **패킷 순서/동기화 중요**.

#### ② 메모리 구조 파악
`forge()`에서 실제로는 `size + 0x20`만큼 할당하고, 뒤 `0x20`에 **내부 트레일러(메타데이터)** 를 저장함.

개념적 구조:
```c
[data (size bytes)] [trailer (0x20 bytes)]
```

즉, 트레일러를 읽거나 쓰면 내부 검증값/함수 호출 로직에 개입 가능.

---

### 2) Root cause

#### 취약점 A — `observe` / `tune` 경계 검사 오류 (OOB on trailer)
`observe`와 `tune`가 원래 `size`까지만 접근해야 하는데, 실제로는 `size + 0x20`까지 허용함.

결과:
- `observe`로 트레일러 leak 가능
- `tune`로 트레일러 overwrite 가능

#### 취약점 B — `shred` Use-After-Free
`shred`는 `free(ptr)`만 하고 `slot->ptr = NULL`을 하지 않음.

결과:
- `observe`/`tune`로 **free된 청크에 계속 접근 가능 (UAF)**

이걸 이용하면 큰 청크 free 후 unsorted bin 관련 포인터를 읽어서 **libc 주소 leak** 가능.

---

### 3) Exploit

#### Step 1. `/bin/sh` shard 생성
slot0에 `/bin/sh\x00`를 넣고 생성한다.

- 나중에 `fire()`가 호출할 함수를 `system`으로 바꾸면
- `rdi = shard ptr` 형태라서 `system("/bin/sh")`가 됨

#### Step 2. trailer leak → cookie + PIE leak
`observe(slot0, off=size0, n=0x20)`로 트레일러 0x20 바이트를 읽는다.

트레일러 값들(`a,b,base,rnd`)로부터:

- `cookie`
- `idle` 함수 주소
- `PIE base`

를 복원할 수 있다.

즉, 이후 `fire()`가 기대하는 내부 무결성 값을 맞춰서 위조할 준비가 됨.

#### Step 3. UAF로 libc leak
큰 청크(slot1)를 만들고, top consolidation 방지를 위해 가드 청크(slot2)를 하나 더 만든다.

- `forge(slot1, big)`
- `forge(slot2, small)` ← guard
- `shred(slot1)`
- `observe(slot1, ...)` ← UAF read

free된 큰 청크 내부에 남아 있는 unsorted bin 포인터를 읽어서 `libc base`를 구한다.

#### Step 4. trailer 위조 (target = system)
slot0의 트레일러를 `tune()`으로 덮어써서, `fire()`가 복원하는 함수 포인터가 `system`이 되게 만든다.

핵심은:
- 검증식/복원식에 맞는 형태로 `f0, f1, f2, f3`를 구성하는 것
- `f2`는 `base_ptr` (slot0의 데이터 시작 주소)
- 결과적으로 `fire(slot0)`가 `system(base_ptr)` 호출

#### Step 5. `sync` 토큰 계산 후 `fire`
`sync()`는 토큰 검증을 통과해야 `fire()` 가능하다.

토큰은 현재 epoch와 트레일러 일부 하위 dword를 조합해서 계산됨.  
정확히 계산한 토큰으로 `sync(slot0, token)` → `fire(slot0)` 호출.

그 뒤 쉘에서 플래그 읽기:
```sh
/bin/cat /srv/app/flag.txt
```

---

### 4) Why it works

이 익스가 성립하는 이유는 **검증 로직 자체를 깨는 게 아니라,   
검증 로직이 믿는 데이터(트레일러)를 우리가 조작**하기 때문이다.

정리하면:

1. `observe/tune` 버그로 트레일러 접근 가능  
2. 트레일러 leak으로 `cookie`, PIE 등 **검증에 필요한 비밀값** 확보  
3. `shred` UAF로 libc leak → `system` 주소 확보  
4. 트레일러를 유효한 형태로 위조 → `fire()` 검증 통과  
5. `fire()`가 최종적으로 `system("/bin/sh")` 실행

즉, **메모리 안전성 붕괴(UAF/OOB) + 로직 신뢰 붕괴(위조된 트레일러)** 가 결합

---

## Solver
not script

```python
# 1) connect
# 2) forge slot0 with "/bin/sh\x00"
# 3) observe(slot0, size0, 0x20) -> trailer leak
#    -> recover cookie / pie
# 4) forge big slot1 + guard slot2
# 5) shred(slot1), observe(slot1, 0, 0x40) -> libc leak
#    -> recover libc_base, system
# 6) craft fake trailer for slot0 so fire() resolves to system(base0)
# 7) tune(slot0, size0, fake_trailer)
# 8) compute sync token from current epoch + fake trailer fields
# 9) sync(slot0, token)
# 10) fire(slot0)
# 11) send "cat /srv/app/flag.txt"
```

---
<img width="810" height="356" alt="image" src="https://github.com/user-attachments/assets/a77aae79-bc5f-446f-b1c2-abcff9eb821e" />
---

