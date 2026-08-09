---
marp: true
theme: default
paginate: true
size: 16:9
style: |
  section {
    font-size: 28px;
  }
  h1 { font-size: 40px; }
  h2 { font-size: 32px; }
  table { font-size: 22px; }
  footer { font-size: 14px; color: #666; }
  .small { font-size: 20px; }
  .muted { color: #555; }
  section.fig {
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
  }
  section.fig h2 { margin-bottom: 0.3em; }
  section.fig img {
    display: block;
    margin: 0 auto;
    max-height: 520px;
    width: auto;
    object-fit: contain;
  }
  section.backup h2::before {
    content: "[Backup] ";
    color: #888;
    font-weight: 600;
  }
---

<!--
Present: slides 1–9 (main). Rest = backup if asked.
Export:
  npx @marp-team/marp-cli docs/0809report.md -o docs/0809report.pdf
Older Phase-A deck (historical only): docs/0806report.md
-->

# ESP32 Multimodal NIDS — Status Update

**2026.08.09** · matched-load · deployable `nids-counts`


---

## Bottom line (now)

1. **Density contract fixed** — firmware `win_pkts` / `win_dens`; offline windows match on-device counts.
2. **Matched-load collected & trained** — NORMAL includes busy (label 0) + DEAUTH / SYN / ARP (START/STOP).
3. **Multimodal research still stands** — HIDS matters; shallow trees turn it into a **stress proxy** (heap → then `udpfail`).
4. **Deploy export ≠ drop HIDS** — board runs **nids-counts** (deauth / packet counts; HIDS+RSSI neutralized at train time).
5. **Board smoke:** IDLE **stable** · DEAUTH **fires** · SYN/ARP left weak on purpose (not worth a smoke test).
6. **B′ dual-expert offline done** (gated OR). **Ask:** lab → **AUTH_FLOOD**; full ARP features after meeting.


---

## What we are building

**Edge window IDS** on ESP32 (not a per-packet firewall):

- **Sense:** promiscuous 802.11 + host counters  
- **Decide:** shallow DT every **100 ms** → `model.h`  
- **Act:** HIPS **off** (until FPR story is deployable)

| Layer | Still in the project? | Role now |
|-------|----------------------|----------|
| Data + HIDS fields | **Yes** | Collected; used in ablations / narrative |
| Offline full / RF / PCA / LDA | **Yes** | Analysis & advisor pack |
| On-device `nids_predict` | **nids-counts** | Stable WIDS-lite for demo / low FP |

<p class="small muted">HIDS is not deleted — it is not the sole split for the MCU tree right now.</p>


---

## Pipeline this cycle

```
flash win_* firmware → matched-load capture
  → aggregate [firmware] → balance PASS
  → train + heap / export ablations
  → board: IDLE + DEAUTH smoke
```

| Capture | Role |
|---------|------|
| `20260809_000851` | Matched-load train + board model |
| Density short busy `20260806_231142` | Contract validation (done) |

<p class="small muted">Failed / trial CSVs archived under `data/archive/` — not used for metrics.</p>


---

## Matched-load numbers (hold-out)

Dataset: 6354 windows · NORMAL 4947 · DEAUTH 656 · SYN 495 · ARP 256 · **balance PASS**

| Export | F1 | FPR | What the tree uses | Board IDLE |
|--------|----:|----:|--------------------|------------|
| full multimodal | 0.54 | **0.48** | mostly **`udpfail`** | — |
| nids-only (no HIDS) | 0.63 | 0.06 | **rssi_var / snr** | **FAIL** (always yellow) |
| **nids-counts** | 0.57 | 0.06 | **deauth / pkts** | **PASS** |

Per-attack recall (**nids-counts**): DEAUTH ~0.80 · SYN ~0.37 · ARP ~0.02  

<p class="small muted">Matched-load cut heap dominance & busy FP vs old stress-proxy behavior; deploy tree trades L2 recall for stability.</p>


---

## Why neutralize HIDS for deploy?

| Evidence | Takeaway |
|----------|----------|
| Full matched tree | Heap importance ↓, but **`udpfail` takes over** → high FPR |
| nids-only on device | RF stats **don’t transfer** across environments |
| nids-counts on device | IDLE quiet; DEAUTH windows show high `deauth`/`tgt` |

**Research story:** multimodal + HIDS ablation still required.  
**Product story:** MCU ships a **stable subset** until dual-expert / better HIDS features exist.


---

## Board smoke (nids-counts)

| Scenario | Result |
|----------|--------|
| IDLE | Long stretches `attack=0`; almost no inference spam |
| DEAUTH | `[INFERENCE] attack window` with large `deauth` / `tgt` |
| SYN / ARP | **Skipped** — offline already weak; won’t change the Ask |

Note: `wifi: This was attack!!! … SA Query` is **ESP-IDF**, not `nids_predict`.


---

## B′ Dual-expert (offline — HIDS back as 2nd path)

Same matched dataset · Expert **W** = nids-counts · Expert **H** = HIDS-only · fusion offline

| Model | F1 | FPR | ARP | SYN | DEAUTH |
|-------|----:|----:|----:|----:|-------:|
| W (deploy today) | 0.57 | **0.06** | 0.02 | 0.37 | 0.80 |
| H alone | 0.60 | 0.35 | **1.00** | **0.92** | 0.94 |
| W∨H naive | 0.57 | **0.40** | 1.00 | 0.94 | 0.96 |
| **W∨H (H if p≥0.85)** | **0.63** | **0.09** | 0.02 | **0.49** | **0.96** |

- HIDS is **not abandoned** — it recovers stress-shaped attacks offline.  
- Naive OR is not deployable; **gated OR** is the practical fusion.  
- **ARP still needs new air features** (full B after the meeting).


---

## Offline models (if asked)

- Pipeline: **PCA / LDA**, DT **hyperparam grid**, **RF** (+ optional boosters).  
- Deeper DT offline F1 **~0.72** vs MCU depth=4 **~0.54**.  
- Dual-expert script: `host/train/dual_expert_eval.py` → `docs/figures/dual_expert_20260809.json`.


---

## Proposed next (ordered)

| Order | Track | Status |
|-------|--------|--------|
| 1 | **B′ dual-expert offline** | **Done** (gated OR numbers above) |
| 2 | **C AUTH_FLOOD** lab day | Next experiment — handbook ready |
| 3 | **Full B** ARP/SYN air features | After 08/13 — firmware + recollect |

**Not next:** blind matched re-collect · HIPS on · lock Git · MCU ensemble chase.


---

## Ask

1. **OK to run Phase C (`AUTH_FLOOD`) as the next lab capture?**  
2. **OK to schedule full ARP feature work after this meeting** (dual-expert does not fix ARP visibility)?

**Our lean:** keep MCU on **nids-counts** · present B′ gated OR as HIDS path · lab → **AUTH** · then ARP features.


---

<!-- _class: backup -->
## Lab sketch

```
Kali  -- air --> ESP32 (STA + promiscuous)
Kali  -- START/STOP --> Collector (Pi / Mode P)
ESP32 -- syslog (win_*) --> Collector → windows → model.h
```

HIPS off while iterating. Hotspot + host-only label path as in runbook.


---

<!-- _class: backup -->
## Export variants (same `model.h` layout)

| Flag | Neutralized at train | Intent |
|------|----------------------|--------|
| `full` | — | Multimodal DT (high FPR here) |
| `nids-only` | all HIDS | Wireless including RSSI |
| **`nids-counts`** | HIDS + rssi/snr | Deploy / board smoke |
| `no-heap` | heap only | Ablation |

```powershell
python host/train/analyze_and_train.py `
  --dataset data/windows/nids_windows_20260809_000851.csv `
  --export-variant nids-counts
```


---

<!-- _class: backup -->
## Feature groups

| | Features |
|--|----------|
| Counts / WIDS | `total_packets`, `packet_density`, `beacon/deauth/probe/auth`, `deauth_targeted`, `seq_jump` |
| RF soft | `rssi_mean`, `rssi_var`, `snr_mean` |
| HIDS | `heap`, `minheap`, `reconn`, `qpeak`, `udpfail`, `backlog` |

nids-counts train: HIDS + RF soft held at NORMAL median → splits on deauth / counts.


---

<!-- _class: backup -->
## Artifacts

| Path | Content |
|------|---------|
| `docs/0809report.md` | **This deck** |
| `docs/0806report.md` | Historical Phase-A ask (superseded for meetings) |
| `note/private/README.md` | Index + short/mid/long plan |
| `note/private/eval/matched_load_eval_20260809.md` | Numbers + board notes |
| `docs/figures/eval_metrics*.json` | Metrics snapshots |
| `main/model.h` | Current **nids-counts** export |


---

<!-- _class: backup -->
## Heap / export ablation (figure)

![w:900](figures/ablation_heap.png)


---

<!-- _class: backup -->
## Decision tree (current export)

![w:920](figures/decision_tree_structure.png)
