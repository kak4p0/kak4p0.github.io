---
title: "[Rev] safe not safe"
description: Writeup for "safe not safe" from BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Rev]
toc: true
comments: false
---

# safe not safe (BITS CTF 2026)

---

- **Name:** safe not safe
- **Category:** Rev
- **Description:** I forgot the password to my smart safe :( Luckily, I was able to dump the firmware.
- **Difficulty:** ★★☆☆☆

---

## TL;DR

The program uses `/dev/urandom` which looks secure, but both `challenge` and `response` are XORed with the **same random value** — so it cancels out.

We don't need to know the `/dev/urandom` value at all.
Just reproduce the time-based PRNG (`srand(time)` + `rand()`), and we can calculate the correct response from the challenge alone.

Successfully resetting the password prints the flag from `/dev/vda`.

**Flag:** `BITSCTF{7h15_41n7_53cur3_571ll_n07_p47ch1ng_17}`

---

## Overview

This is an ARM binary (`lock_app`) running inside QEMU.
Connecting to the service drops us into a **shell (`/ $`)** first — we have to run `/challenge/lock_app` manually.

Program menu:
1. Enter access code
2. Reset password
3. Exit

Option 1 is a dead end (not implemented).
**Option 2 (Reset password) is the target.**

Passing the reset verification makes the program read `/dev/vda` and print the flag.

---

## Solution

### 1) Recon

#### Files provided

- `zImage` — ARM Linux kernel
- `run.sh` — QEMU launch script
- `Dockerfile`
- `flag.txt` — dummy flag

`run.sh` connects the real flag as `/dev/vda`.
So the goal is to make `lock_app` read `/dev/vda`.

#### initramfs analysis

Extracting the initramfs from `zImage` gives us `/challenge/lock_app`.

The `/init` script:
- Sets up the system
- Sets `lock_app` as setuid root
- Drops into `/bin/sh`
- Prompts the user to run `/challenge/lock_app`

This means the shell appears first, not the menu — something to handle carefully in automation scripts.

#### Binary strings

Key strings found in the binary:

- `The current time is: %lu`
- `Your challenge code is: %06u`
- `Response code:`
- `PASSWORD RESET SUCCESSFUL`
- `Here's a gift: %s`
- `/dev/vda`

From this, the reset flow is clear:
1. Program shows a challenge code
2. User enters a response code
3. If correct → prints the flag from `/dev/vda`

---

### 2) Root Cause

The bug is in how `challenge` and `response` are generated.

The program uses both `/dev/urandom` and `rand()` to look secure, but the math is flawed.

Let:
- `u` = value read from `/dev/urandom`
- `x`, `y` = values derived from `rand()` (seeded by time — reproducible)

Then:
```
challenge = u ^ F(x, y)
response  = u ^ G(x, y)
```

Since the user sees `challenge` and must produce `response`, we can compute:

```
response = challenge ^ F(x, y) ^ G(x, y)
```

**`u` cancels out completely.**

This means `/dev/urandom` provides zero security here.
As long as we can reproduce `x` and `y` from the time seed, we can calculate the response.

---

### 3) Exploit

The program prints `init_time` when it starts.
`reset_time` is always shortly after `init_time`, so we brute-force a small delta:

```
reset_time = init_time + delta   (delta in range 0..20)
```

For each candidate `reset_time`, compute the response and try it.
When the correct response is entered:

```
PASSWORD RESET SUCCESSFUL
Here's a gift: BITSCTF{...}
```

#### Formula

```
challenge = u ^ ((x * 31337 + y) % 1000000)
response  = u ^ ((x ^ y)         % 1000000)
```

Therefore (u cancels):

```
response = challenge
         ^ ((x * 31337 + y) % 1000000)
         ^ ((x ^ y)         % 1000000)
```

`x` and `y` come from `rand()` seeded with `reset_time`, so they are fully reproducible.

---

### 4) Why it works

**Simple analogy:**
The developer hid a secret number `u` inside both challenge and response, but used XOR both times — so when you compute one from the other, `u` cancels itself out. The "randomness" ends up protecting nothing.

**Technically:**
The response depends only on:
- The `challenge` value (visible to us)
- Time-seeded `rand()` output (reproducible with the printed `init_time`)
- A small brute-forceable `delta`

This isn't a cryptographic attack — it's a **broken PRNG/XOR design** where the random value was used incorrectly.

---

## Solver

### Key logic

```
1.  Connect to the remote service
2.  Wait for shell prompt (/ $)
3.  Run /challenge/lock_app
4.  Parse "The current time is: <init_time>"
5.  Select menu option 2 (Reset password)
6.  Parse "Your challenge code is: <challenge>"
7.  Brute-force delta (0..20):
      reset_time = init_time + delta
      seed rand() with reset_time
      compute x, y from rand() + table lookup
      response = challenge
               ^ ((x * 31337 + y) % 1000000)
               ^ ((x ^ y)         % 1000000)
8.  Send each candidate response
9.  On "PASSWORD RESET SUCCESSFUL" → read flag
```

### Formula summary

```
response = challenge
         ^ ((x * 31337 + y) % 1000000)
         ^ ((x ^ y)         % 1000000)

where x, y = rand()-derived values seeded by reset_time
```
