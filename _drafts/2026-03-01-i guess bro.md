---
title: "[Rev] i guess bro"
description: Writeup for "i guess bro" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Rev]
toc: true
comments: false
---

# i guess bro (EHAX CTF 2026)

---

- **Name:** i guess bro
- **Category:** Rev
- **Description:** meh yet another crackme challenge
- **Difficulty:** ★☆☆☆☆

---

## TL;DR

The binary stores an **encrypted 35-byte flag** in `.rodata`.  
At runtime, it **decrypts** it with a simple XOR formula and compares it with your input.

Decryption rule:

```
plain[i] = enc[i] ^ (7*i) ^ 0xA5    for i = 0..34
```

So we only need to extract the encrypted bytes and apply the same rule to print the flag.

---

## Overview

This challenge is a classic crackme:

- It asks: `Enter the flag:`
- It checks the **length** first (must be 35).
- Then it creates the expected flag string **inside the program** by decrypting a fixed byte array.
- Finally it compares your input to that decrypted result.

Important note for beginners:

- If a program compares your input to a secret value, it must have that secret (or the data to build it) somewhere in the binary.
- Reversing is often about finding that comparison and recovering the secret.

---

## Solution

### 1) Recon

Check the file type:

```bash
file chall
```

Result (summary):

- `ELF 64-bit`
- **RISC-V (riscv64)**
- **statically linked**
- **stripped**

Because it is RISC‑V, you cannot run it natively on x86_64 WSL.  
You can still solve it by static analysis, or run it with QEMU:

```bash
sudo apt update
sudo apt install -y qemu-user
qemu-riscv64 ./chall
```

Also, `strings` already shows useful hints:

```bash
strings -n 3 chall | head
```

You can see messages like:

- `Enter the flag:`
- `Wrong length! ...`
- `Correct! ...`
- `Wrong! ...`

These messages usually mean: **read input → check length → compare**.

---

### 2) Root cause

The “security issue” of this crackme is simple:

✅ The expected flag is not derived from your input in a hard-to-invert way.  
✅ The flag is stored in the program as encrypted bytes and decrypted at runtime.  

So the program contains everything we need to reconstruct the flag offline.

In the disassembly/decompiler, you can find logic like:

- `if (strlen(input) != 35) fail`
- `for i in 0..34: out[i] = data[i] ^ (7*i) ^ 0xA5`
- `memcmp(input, out, 35)`

---

### 3) Exploit (how we solve it)

We “exploit” the weak protection by doing the same steps as the program:

1. Locate the encrypted 35-byte block in the file (usually in `.rodata`).
2. Apply the XOR decryption formula.
3. Print the plaintext result.

Why this is easy:

- XOR is reversible.
- The key is not secret. It is in the code: `(7*i)` and `0xA5`.

---

### 4) Why it works

XOR has a special property:

- If `A ^ K = B`, then `B ^ K = A`.

So encryption and decryption are the same operation.

The binary does:

```
plain[i] = enc[i] ^ key[i]
```

We can do the exact same thing and get the same `plain[i]`.

Also, the program helps us with structure:

- Length must be 35.
- Flag format starts with `EH4X{` and ends with `}`.

That makes it even easier to find the correct encrypted block.

---

## Solver

Save as `solve.py` and run:

```bash
python3 solve.py ./chall
```

### `solve.py`

```python
#!/usr/bin/env python3
import argparse
import sys

N = 35
PREFIX = b"EH4X{"
SUFFIX = b"}"

def decrypt_block(enc: bytes) -> bytes:
    return bytes(enc[i] ^ ((7 * i) & 0xFF) ^ 0xA5 for i in range(N))

def is_printable_ascii(bs: bytes) -> bool:
    return all(32 <= b < 127 for b in bs)

def main():
    ap = argparse.ArgumentParser(description="Solve: I GUESS BRO (riscv crackme)")
    ap.add_argument("path", nargs="?", default="chall", help="path to chall (default: ./chall)")
    ap.add_argument("--show-offset", action="store_true", help="print file offset too")
    args = ap.parse_args()

    try:
        buf = open(args.path, "rb").read()
    except OSError as e:
        print(f"[!] Cannot open file: {e}", file=sys.stderr)
        sys.exit(1)

    # Pre-compute encrypted form of known plaintext pieces for fast filtering.
    enc_prefix = bytes(PREFIX[i] ^ ((7 * i) & 0xFF) ^ 0xA5 for i in range(len(PREFIX)))
    enc_last = SUFFIX[0] ^ ((7 * (N - 1)) & 0xFF) ^ 0xA5

    hits = []
    limit = len(buf) - N + 1
    for off in range(limit):
        # Quick filters to reduce false positives.
        if buf[off:off + len(PREFIX)] != enc_prefix:
            continue
        if buf[off + (N - 1)] != enc_last:
            continue

        enc = buf[off:off + N]
        plain = decrypt_block(enc)

        # Validate: format + printable + extra checksum used by the binary.
        if not (plain.startswith(PREFIX) and plain.endswith(SUFFIX)):
            continue
        if not is_printable_ascii(plain):
            continue
        if sum(plain) != 3243:
            continue

        hits.append((off, plain))

    if not hits:
        print("[!] Flag not found. Maybe this is a different build.")
        sys.exit(2)

    for off, flag in hits:
        if args.show_offset:
            print(f"{flag.decode()}  (offset=0x{off:x})")
        else:
            print(flag.decode())

if __name__ == "__main__":
    main()
```

---

### Example output

```
EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}
```

---
<img width="620" height="63" alt="스크린샷 2026-02-28 073519" src="https://github.com/user-attachments/assets/3b1353d1-b1ec-4a2f-bb57-68316a5004bb" />
---

