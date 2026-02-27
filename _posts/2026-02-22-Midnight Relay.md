---
title: "[Pwn] Midnight Relay"
description: Writeup for "Midnight Relay" from BITS CTF 2026.
date: 2026-02-22 01:00:00 +0900
categories: [CTF, BITS CTF 2026]
tags: [Pwn]
toc: true
comments: false
---

# Midnight Relay (BITS CTF 2026)

---

- **Name:** Midnight Relay
- **Category:** Pwn
- **Description:** A fallback relay was brought online during a midnight outage.
- **Difficulty:** ★☆☆☆☆

---

## TL;DR

`midnight_relay` is solved by chaining a heap UAF and an out-of-bounds read/write on an internal trailer structure, ultimately replacing a function pointer with `system` to get a shell.

**Attack chain:**

1. `observe`/`tune` allow access up to `size + 0x20` → read/write the internal **trailer**
2. `shred` frees a chunk but doesn't null the pointer → **UAF**
3. Trailer leak → recover `cookie` and `PIE base`
4. UAF on a large freed chunk → **libc leak**
5. Forge a fake trailer + compute `sync` token → call `fire()` → `system("/bin/sh")`

**Flag:** `BITSCTF{m1dn1ght_r3l4y_m00nb3ll_st4t3_p1v0t}`

---

## Overview

The binary uses a custom packet protocol (`op / key / len / payload`) and stores "shards" in `slot[]`.

**Commands:**

- `forge` — allocate a shard
- `tune` — write to a shard
- `observe` — read from a shard
- `shred` — free a shard
- `sync` — verify a token, then arm
- `fire` — call a function based on the shard's internal trailer

All standard protections are enabled (PIE / NX / RELRO / Canary),
so the goal is to exploit memory bugs and corrupt internal state.

---

## Solution

### 1) Recon

#### Protocol

Each packet has the format:

```
op (1B) | key (1B) | len (2B LE) | payload
```

`key` is a checksum based on the payload and an internal epoch value.
The epoch updates after every successful packet, so **packet order matters**.

#### Memory Layout

`forge()` allocates `size + 0x20` bytes. The last `0x20` bytes hold an **internal trailer** with metadata used by `fire()`.

```
[ data (size bytes) ][ trailer (0x20 bytes) ]
```

Reading or writing past `size` lets us access the trailer directly.

---

### 2) Root Cause

#### Bug A — OOB on trailer (`observe` / `tune`)

`observe` and `tune` should only access up to `size` bytes,
but they actually allow access up to `size + 0x20`.

- `observe` → **leak the trailer**
- `tune` → **overwrite the trailer**

#### Bug B — Use-After-Free (`shred`)

`shred` calls `free(ptr)` but never sets `slot->ptr = NULL`.

So after freeing, we can still call `observe` or `tune` on the same slot.
On a large freed chunk, the **unsorted bin pointers** left behind can be read to **leak a libc address**.

---

### 3) Exploit

#### Step 1 — Create `/bin/sh` shard (slot0)

Forge slot0 with the content `/bin/sh\x00`.

When `fire(slot0)` is called and the function pointer is replaced with `system`,
it will call `system(ptr_to_shard)` = `system("/bin/sh")`.

#### Step 2 — Trailer leak → cookie + PIE

```
observe(slot0, offset=size0, len=0x20)
```

This reads the trailer. From the trailer values, we can recover:

- `cookie` (internal integrity value)
- `idle` function address → `PIE base`

These are needed later to forge a valid trailer.

#### Step 3 — UAF → libc leak

```
forge(slot1, big_size)   # large chunk
forge(slot2, small_size) # guard chunk (prevents top consolidation)
shred(slot1)             # free slot1 (UAF: pointer not cleared)
observe(slot1, 0, 0x40)  # read freed memory
```

The freed large chunk retains **unsorted bin fd/bk pointers**.
Reading them gives us `libc base`, from which we calculate `system`.

#### Step 4 — Forge fake trailer (slot0)

Use `tune(slot0, offset=size0, fake_trailer)` to overwrite the trailer.

The fake trailer is constructed so that when `fire()` reads it and restores the function pointer, it gets `system` instead of the original function.

Key fields:
- `f2` = `base_ptr` (address of slot0's data = `"/bin/sh"`)
- Other fields computed to satisfy `fire()`'s internal checks using the leaked `cookie` and `PIE base`

#### Step 5 — `sync` token → `fire`

`sync()` requires a valid token before `fire()` is allowed.

The token is computed from the current epoch and a field in the trailer.
After computing the correct token:

```
sync(slot0, token)
fire(slot0)
```

`fire()` calls `system("/bin/sh")` → interactive shell.

Then read the flag:

```sh
cat /srv/app/flag.txt
```

---

### 4) Why it works

The key idea is: **we don't break the verification logic — we control the data it trusts.**

- `observe`/`tune` bugs give us access to the trailer
- Trailer leak gives us the secret values (`cookie`, PIE) needed to forge valid data
- UAF gives us `libc base` → `system` address
- Forged trailer passes `fire()`'s checks and redirects execution to `system`
- Correct `sync` token satisfies the final gate

In short: **memory safety bugs (UAF + OOB) combine with logic trust abuse (forged trailer)** to achieve full RCE.

---

## Solver

```python
# 1)  Connect to target
# 2)  forge(slot0, "/bin/sh\x00")
# 3)  observe(slot0, size0, 0x20)
#       -> leak trailer
#       -> recover cookie, PIE base
# 4)  forge(slot1, big) + forge(slot2, small_guard)
# 5)  shred(slot1)
#     observe(slot1, 0, 0x40)  # UAF
#       -> leak libc base, compute system()
# 6)  build fake_trailer:
#       f2 = base_ptr(slot0)
#       other fields satisfy fire() checks
# 7)  tune(slot0, size0, fake_trailer)
# 8)  token = compute(epoch, trailer_field)
#     sync(slot0, token)
# 9)  fire(slot0)  ->  system("/bin/sh")
# 10) cat /srv/app/flag.txt
```

---

## Flag

```
BITSCTF{m1dn1ght_r3l4y_m00nb3ll_st4t3_p1v0t}
```
