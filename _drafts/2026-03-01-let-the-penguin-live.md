---
title: "[Forensics] let-the-penguin-live"
description: Writeup for "let-the-penguin-live" from EHAX CTF 2026.
date: 2026-03-01 09:00:00 +0900
categories: [CTF, EHAX CTF 2026]
tags: [Forensics]
toc: true
comments: false
---

# painter (EHAX CTF 2026)

---

- **Name:** let-the-penguin-live
- **Category:** Forensics
- **Description:** there was a painter working for a security company who attempted to deceive one of the employees. To do so, he said flag format EH4X{hihihihi} author - stapat
- **Difficulty:** ★★☆☆☆

---

## TL;DR

A `.mkv` file contains **two almost identical audio tracks**.
Subtracting one track from the other reveals a hidden signal.
Visualizing that signal as a **spectrogram** shows the flag as text.

```
EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_f1les}
```

---

## Overview

| Field | Info |
|---|---|
| Challenge | LET-THE-PENGUIN-LIVE |
| Category | Audio Steganography |
| Points | 408 |
| Author | mahekfr |
| Flag | `EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_f1les}` |

**Challenge description:**

> "In a colony of many, one penguin's path is an anomaly.
> Silence the crowd to hear the individual."

**Files given:**
- `challenge.mkv`
- `spectrogram_signal.png` (a noisy hint image)

---

## Solution

### 1) Recon — What is inside the file?

First, we check the file structure using `ffprobe`.

```bash
ffprobe -v quiet -print_format json -show_streams challenge.mkv
```

**Result:** The `.mkv` file has **3 streams** — one video and **two audio tracks**!

```
Stream 0: video  (h264)
Stream 1: audio  (flac)  ← Track 1
Stream 2: audio  (flac)  ← Track 2
```

> 💡 This is the first clue. Normal videos have only one audio track.
> Having two tracks is suspicious.

---

### 2) Root Cause — What is the trick?

The hint says **"Silence the crowd to hear the individual."**

This means:
- The two audio tracks sound almost the **same** (the crowd)
- But one track has a **tiny hidden signal added** (the individual)
- If you **subtract** Track 2 from Track 1, the identical parts cancel out
- Only the **hidden signal remains**

This technique is called **audio phase cancellation**.

```
Track1 = Background music + Hidden signal
Track2 = Background music

Track1 - Track2 = Hidden signal  ✅
```

---

### 3) Exploit — Step by step

#### Step 1: Extract both audio tracks

```bash
ffmpeg -i challenge.mkv -map 0:a:0 track1.wav
ffmpeg -i challenge.mkv -map 0:a:1 track2.wav
```

#### Step 2: Subtract track2 from track1

```bash
ffmpeg -i track1.wav -i track2.wav \
  -filter_complex "[0:a][1:a]amix=inputs=2:weights=1 -1[out]" \
  -map "[out]" diff.wav
```

> This mixes Track1 and an **inverted** Track2 together.
> Inverted means every sample value is flipped (positive → negative).
> So the same parts cancel each other out perfectly.

#### Step 3: Visualize the hidden signal as a spectrogram

A **spectrogram** is a 2D image that shows:
- X-axis = Time
- Y-axis = Frequency
- Brightness = Volume at that frequency

```python
import numpy as np
import scipy.io.wavfile as wav
import matplotlib.pyplot as plt
from scipy import signal

# Load the difference signal
sr, data = wav.read('diff.wav')
sig = data[:, 0].astype(np.float32)

# Generate spectrogram
f, t, Sxx = signal.spectrogram(sig, fs=sr, nperseg=4096, noverlap=3900)
Sxx_db = 10 * np.log10(Sxx + 1e-10)

# Plot
plt.figure(figsize=(20, 8))
plt.pcolormesh(t, f, Sxx_db, shading='auto', cmap='hot',
               vmin=np.percentile(Sxx_db, 40),
               vmax=np.percentile(Sxx_db, 99.5))
plt.ylim(0, 8000)
plt.xlabel('Time (s)')
plt.ylabel('Frequency (Hz)')
plt.title('Hidden Signal Spectrogram')
plt.savefig('spectrogram_out.png', dpi=150, bbox_inches='tight')
```

#### Step 4: Read the flag from the image

The spectrogram shows **two lines of text** burned into the frequency domain:

```
Line 1: EH4X{0n3_tr4ck_m1nd
Line 2: _tw0_tr4ck_f1les}
```

Reading the leet speak:
- `0` = o
- `n3` = ne
- `m1nd` = mind
- `tw0` = two
- `f1les` = files

**Flag: `EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_f1les}`**

---

### 4) Why it works

When you **draw text into a spectrogram**, you are writing into frequency space at specific times and frequencies. If you then convert that image **back into audio**, it becomes a sound signal that is nearly inaudible — especially when mixed with louder background music.

The hidden signal has very small amplitude (max ~150) compared to the background music (max ~4500). That is roughly **30x quieter**, so you cannot hear it at all.

Only by removing the background (phase cancellation) and then visualizing the remaining signal as a spectrogram can you see the hidden text.

```
Audio → spectrogram image → looks like text ✅
Audio is quiet enough to hide inside another audio track ✅
Removing background reveals the hidden image ✅
```

---

## Solver

Full Python solve script:

```python
import subprocess
import numpy as np
import scipy.io.wavfile as wav
import matplotlib.pyplot as plt
from scipy import signal

# ── Step 1: Extract tracks ──────────────────────────────────────────
subprocess.run(['ffmpeg', '-i', 'challenge.mkv', '-map', '0:a:0', 'track1.wav', '-y'],
               capture_output=True)
subprocess.run(['ffmpeg', '-i', 'challenge.mkv', '-map', '0:a:1', 'track2.wav', '-y'],
               capture_output=True)

# ── Step 2: Compute difference ──────────────────────────────────────
sr, d1 = wav.read('track1.wav')
sr, d2 = wav.read('track2.wav')

diff = d1.astype(np.float32) - d2.astype(np.float32)

# Save amplified version so you can also listen to it
amplified = np.clip(diff * 100, -32768, 32767).astype(np.int16)
wav.write('diff_amplified.wav', sr, amplified)

# ── Step 3: Generate spectrogram ────────────────────────────────────
sig = diff[:, 0]  # use channel 0

f, t, Sxx = signal.spectrogram(sig, fs=sr, nperseg=4096, noverlap=3900)
Sxx_db = 10 * np.log10(Sxx + 1e-10)

plt.figure(figsize=(20, 8))
plt.pcolormesh(t, f, Sxx_db, shading='auto', cmap='hot',
               vmin=np.percentile(Sxx_db, 40),
               vmax=np.percentile(Sxx_db, 99.5))
plt.ylim(0, 8000)
plt.xlabel('Time (s)')
plt.ylabel('Frequency (Hz)')
plt.title('LET-THE-PENGUIN-LIVE — Hidden Signal Spectrogram')
plt.tight_layout()
plt.savefig('flag_spectrogram.png', dpi=150, bbox_inches='tight')
print('Saved: flag_spectrogram.png')
print('Flag: EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_f1les}')
```

**Requirements:**
```bash
pip install numpy scipy matplotlib
# ffmpeg must be installed on your system
```

**Run:**
```bash
python3 solve.py
# Then open flag_spectrogram.png and read the flag!
```
---
<img width="1346" height="418" alt="image" src="https://github.com/user-attachments/assets/20a802bf-4fd1-4f97-a903-423c2f574b76" />
---


