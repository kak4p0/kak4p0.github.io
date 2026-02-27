---
title: "[Rev] Pathfinder"
description: Writeup for "name" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Rev]
toc: true
comments: false
---

# Pathfinder (EHAX CTF 2026)

---

- **Name:** Pathfinder
- **Category:** Rev
- **Description:** You can go funky ways
- **Difficulty:** ★☆☆☆☆

---

## TL;DR
- The program asks for a path string using only `N/S/E/W`.
- It validates moves on a hidden **10×10 grid** using “door bits” (exit/entry rules).
- Even if you reach the goal `(9,9)`, your whole path must match a **custom 32‑bit hash**.
- The flag is **not stored directly**. It is generated as: `EHAX{RLE(path)}`.
- The correct path is:
  - `EESSSWWSSSSSSEEEEEEEENNESS`
- The flag is:
  - `EHAX{2E3S2W6S8E2NE2S}`

---

## Overview
This is a reversing + algorithmic challenge.

You are given a Linux binary `pathfinder`. When you answer `y`, it asks:

- `Ok, tell me the best path:`

Your input is a string made of `N`, `S`, `E`, `W`.
Each character moves one cell on a 10×10 board.

The “board” is not printed. It is embedded in the binary (encrypted) and decrypted at runtime.

Your goal:
1. Walk from start `(0,0)` to end `(9,9)` **without breaking the movement rules**.
2. Make sure the **hash of the full path** equals the constant inside the binary.
3. The program then prints a flag derived from your path.

This challenge is **logic-based**, not memory corruption.

---

## Solution

### 1) Recon
Basic recon on WSL Ubuntu:

```bash
file ./pathfinder
chmod +x ./pathfinder
./pathfinder
strings -a ./pathfinder | less
```

What we learn from `strings`:
- It prints `You have what it takes. Flag: %s` on success.
- It prints `Better luck next time.` on failure.

So the binary decides “correct/incorrect” and prints a generated flag.

Next, disassemble / decompile (choose one):
- Ghidra (recommended)
- IDA
- `objdump -d -Mintel ./pathfinder | less`

During reversing, focus on:
- The function that checks each move (`N/S/E/W`)
- The place where it checks `(x,y)` bounds
- The hash calculation function
- The flag formatting function

---

### 2) Root cause (how the challenge is built)
The binary stores a 10×10 grid (100 bytes), but it is **encrypted** in `.rodata`.

At startup, it decrypts it into memory.

Each cell contains a small value (bitmask) that acts like “doors”.
A move is allowed if:
- The current cell has an **exit bit** for that direction, **OR**
- The next cell has an **entry bit** for that direction

This is the important part: it is not “wall vs no wall”.
It is an **OR rule** between the current cell and the next cell.

After you reach `(9,9)`, the binary computes a custom 32‑bit hash of your full path.
Only one path (or very few) will match the required hash constant.

Finally, the flag is built from your path using **RLE compression** (Run‑Length Encoding).

---

### 3) Exploit (practical solving plan)
Because this is not a memory bug, the “exploit” is to **copy the program logic** and solve it offline.

Plan:
1. Extract and decrypt the 100-byte grid from the binary.
2. Implement the exact move rules.
3. Use BFS (Breadth‑First Search) to find a valid path from `(0,0)` to `(9,9)`.
   - BFS naturally finds the **shortest** valid path.
4. Compute the same hash on the candidate path.
5. When the hash matches the target constant, generate the flag with RLE.

This is deterministic and fast.

---

### 4) Why it works
- The move checker is pure logic: no randomness.
- The grid is fixed once decrypted.
- BFS guarantees that if a valid path exists, we will find it (and in shortest length).
- The hash check makes the answer unique: only a path with the correct hash is accepted.
- The flag is not hidden; it is **derived** from the accepted path:
  - `flag = "EHAX{" + RLE(path) + "}"`

So once we replicate the checks, we can compute the same accepted input and the same flag.

---

## Solver
Below is a complete Python solver (`solve.py`) that:
- Reads the binary
- Decrypts the 10×10 grid
- Finds the shortest valid path with BFS
- Verifies the hash
- Prints the flag

> Note: The offsets and constants come from reversing the provided binary.

```python
#!/usr/bin/env python3
from collections import deque
import numpy as np

BIN = "./pathfinder"

def rol32(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def hash_path(s: str) -> int:
    # Custom hash used by the binary
    h = 0xDEADBEEF
    for b in s.encode():
        h ^= b
        h = rol32(h, 13)
        h = (h * 0x045D9F3B) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    return h & 0xFFFFFFFF

def f(i: int) -> int:
    # Per-index transform used during grid decryption
    i &= 0xFFFFFFFF
    eax = ((i << 5) & 0xFFFFFFFF)
    eax = (eax - i) & 0xFFFFFFFF
    eax = (eax + 0x11) & 0xFFFFFFFF
    edx = eax
    eax = ((i << 3) & 0xFFFFFFFF)
    eax = (eax ^ edx) & 0xFFFFFFFF
    eax = (eax ^ 0xFFFFFFA5) & 0xFFFFFFFF
    return eax

def rle(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        j = i
        while j < len(s) and s[j] == s[i]:
            j += 1
        cnt = j - i
        if cnt > 1:
            out.append(f"{cnt}{s[i]}")
        else:
            out.append(s[i])
        i = j
    return "".join(out)

def main():
    data = open(BIN, "rb").read()

    # Encrypted 100-byte grid is stored in .rodata.
    # Offset below is from reversing this specific binary.
    enc = data[0x2020:0x2020 + 100]

    # Decrypt: grid[i] = enc[i] XOR (f(i) & 0xFF)
    grid = bytes([enc[i] ^ (f(i) & 0xFF) for i in range(100)])
    arr = np.frombuffer(grid, dtype=np.uint8).reshape((10, 10))

    # Movement rules (door bits)
    dirs = {'N': (-1, 0), 'S': (1, 0), 'E': (0, 1), 'W': (0, -1)}

    # allow if (current & mask_cur[dir]) OR (next & mask_next[dir])
    mask_cur  = {'N': 0x04, 'S': 0x01, 'E': 0x02, 'W': 0x08}
    mask_next = {'N': 0x01, 'S': 0x04, 'E': 0x08, 'W': 0x02}

    def can_move(x, y, ch):
        dx, dy = dirs[ch]
        nx, ny = x + dx, y + dy
        if not (0 <= nx < 10 and 0 <= ny < 10):
            return False
        cur = arr[x, y]
        nxt = arr[nx, ny]
        return (cur & mask_cur[ch]) != 0 or (nxt & mask_next[ch]) != 0

    # BFS from (0,0) to (9,9)
    start = (0, 0)
    goal = (9, 9)
    q = deque([(start, "")])
    seen = {start}

    path = None
    while q:
        (x, y), p = q.popleft()
        if (x, y) == goal:
            path = p
            break
        for ch in "NSEW":
            if can_move(x, y, ch):
                nx, ny = x + dirs[ch][0], y + dirs[ch][1]
                if (nx, ny) not in seen:
                    seen.add((nx, ny))
                    q.append(((nx, ny), p + ch))

    if path is None:
        print("[-] No path found")
        return

    print("[+] shortest path:", path)
    h = hash_path(path)
    print("[+] hash:", hex(h))

    # Hash constant required by the binary (from reversing)
    TARGET = 0x86BA520C
    if h != TARGET:
        print("[-] Hash mismatch, not accepted by the binary")
        return

    flag = "EHAX{" + rle(path) + "}"
    print("[+] flag:", flag)

if __name__ == "__main__":
    main()
```

Run it:

```bash
python3 solve.py
```

Test the solution against the binary:

```bash
printf "y
EESSSWWSSSSSSEEEEEEEENNESS
" | ./pathfinder
```

Expected flag:

- `EHAX{2E3S2W6S8E2NE2S}`

---
<img width="762" height="118" alt="스크린샷 2026-02-28 054325" src="https://github.com/user-attachments/assets/862f5cf7-ab5a-4b5f-a950-999ffeddf84b" />
---
