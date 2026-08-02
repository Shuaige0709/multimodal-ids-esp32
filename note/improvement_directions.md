# 可改進方向（整理）

更新日期：2026-08-01  

對照對象：組員 `esp32_packet_monitor`（板上 250 ms CSV + WIDS 特徵；決策樹在其資料上 FPR≈0、malicious recall≈98%）。  
相關說明：`note/compare_wids_vs_nids.md`。

---

## 0. 先定主軸（避免兩套並立）

不必預設「以誰的 repo 為主」，用成功標準定：

| 若優先… | 做法 |
|---------|------|
| **偵測數字**（F1／FPR） | 無線特徵向組員對齊；用同一評估協定重跑 |
| **可重現實驗系統**（多攻擊、label、Pi／Serial、上板） | 管線骨架用本 repo，感測特徵合流 |
| **兩者都要** | **一條主線**：特徵契約統一 + 單一正式資料源；另一 repo 當原型／對照 |

建議對外定位（命名）：

> **Multimodal IDS**＝無線面（WIDS 風格）＋主機面（HIDS）  
> 不要硬講「NIDS+WIDS+HIDS」三套並列（WIDS 與 NIDS 在 Wi‑Fi 實驗裡容易重疊、難辯護）。

**不建議：** 整包換成組員 CSV／UDP broadcast 當正式通訊（會拆掉 syslog、discovery、攻擊 label、Mode P/W/S）。

---

## 1. 無線特徵（優先，向組員借）

本專案已有 deauth／probe／auth 計數與 RSSI／SNR，但 WIDS 深度較淺。

| 優先 | 特徵／能力 | 用途 |
|------|------------|------|
| P0 | `deauth_targeted`（打本機或 broadcast） | 降低旁路 deauth 噪音 |
| P0 | `seq_jump`（相對 AP／QoS stream） | 序列異常，不只 raw `seq` |
| P1 | `unique_bssid` / `unique_bssid_window`、OUI | evil twin／多 AP |
| P1 | EAPOL／EAP 計數（取代粗 AUTH proxy） | 握手／認證異常 |
| P2 | `malformed_packets` | 廉價異常訊號 |

實作原則：

- 窗長維持本專案 **100 ms**（與現有訓練契約一致）；組員 250 ms 可當消融對照，不是必換。
- 新欄位進 syslog 與／或 `WINDOW_FEATURES` → **重收資料 → 重訓 `model.h`**。
- 做消融：baseline（現況）vs +WIDS 特徵 vs ±HIDS。

---

## 2. 模型與資料品質

| 問題 | 改進 |
|------|------|
| 舊模型易被 **heap 等 HIDS** 主導 → 假 `[INFERENCE] attack` | `HIPS_ENABLE` 先維持關閉；平衡資料重訓後再開 |
| 測試集偏 SYN、NORMAL／ARP 偏少 | 正式數字前重收：**NORMAL + DEAUTH + SYN + ARP 均衡** |
| 只報 accuracy 易誤導 | 固定看 **F1、per-class recall、FPR、AUC**；盡量 per-attack |
| 與組員數字無法比 | 對齊：hold-out／是否同場地、malicious 含哪些攻擊、窗長與 label 方式 |

組員結果解讀（參考，非本 repo 數字）：

- 優點：FPR=0、漏報很少 → 說明其 WIDS 特徵對該資料很尖。
- 保留：是否訓練集自評、malicious 是否幾乎只有 deauth、樣本約 3k 列（錄音時間有限）。

---

## 3. 攻擊覆蓋

現有三種與 IDS 面的對應：

| 攻擊 | 偏哪一面 | 在本感測器上 |
|------|----------|--------------|
| Deauth | **WIDS** | subtype 直接可見；兼有 reconn／backlog |
| SYN flood | **NIDS（L3/L4）** | 加密下多為密度／IPAT／佇列側寫 |
| ARP spoof | **NIDS（L2 LAN）** | 同樣難直接見 ARP opcode；偏流量＋主機壓力 |

### 3.1 先做（不必加攻擊種類）

- 三種攻擊 + NORMAL **樣本量與時長拉齊**
- Deauth 場次用 Mode **S**（serial）或 Pi OOB，避免只靠同一條 Wi‑Fi UDP

### 3.2 若要加第四類（強化 WIDS 故事）

優先於再堆一個 L4 flood：

1. Evil twin／rogue AP（吃 BSSID 窗特徵）
2. Beacon／probe flood
3. Auth／EAPOL 異常場景

### 3.3 若要讓 SYN／ARP「更像經典 NIDS」

需額外路徑（關聯後看協議棧、明文實驗網、或可解析資料幀）；否則論文應誠實寫成 **無線側寫 + 主機壓力**，避免暗示已解析 TCP/ARP。

---

## 4. 收集與可靠性

| 方向 | 說明 |
|------|------|
| Serial standby | 學組員：Wi‑Fi 健康時就開好 COM，deauth 斷線再切，降低開埠 reset |
| Mode 選擇 | Deauth → S 或 P；SYN／ARP → W 或 P 通常夠 |
| live_state | Mode P：Kali 用個人 sync（勿依賴 git 傳 `live_state`）；`sudo -E` 保留 `NIDS_*` |
| Deauth 操作 | 頻道／BSSID 與 AP 一致；打完 `prepare_wifi managed` 或重啟 NetworkManager |
| 可選強化 | 韌體把 AP BSSID／channel 寫進 `live_state`，減少手填 `NIDS_BSSID` |

---

## 5. 工程／架構（中優先）

| 方向 | 說明 |
|------|------|
| 拆模組 | 參考組員：`sniffer`／`metrics`／telemetry 分離，降低 `main.c` 負擔 |
| 特徵契約單一 | `nids_features.py` ↔ 韌體窗填充 ↔ `model.h` 順序鎖定；改特徵必同步三處 |
| 兩 repo 合流 | 抄特徵與 collect 備援邏輯；**不**雙正式資料源 |
| 文件 | 組員對齊用 `compare_wids_vs_nids.md`；實驗日用 `lab_runbook.md` |

---

## 6. 建議執行順序（checklist）

### 短期（效果／可信度）

- [x] 平衡重收工具／checklist：`note/private/phase_a_collection.md` + `host/train/check_dataset_balance.py`
- [x] **Phase A 實測重收（2026-08-02）**：平衡 PASS；DT F1≈0.73／FPR≈0.10；HIDS ablation F1 **+0.28**
- [x] SYN STOP 遺失後處理：`host/train/fix_syn_label_gap.py`（報告需披露校正）
- [x] Deauth 用 Serial standby：`scripts/serial_collector.py --standby`
- [x] 重訓閘門：`analyze_and_train.py --strict-export`（heap importance；本場 heap≈0.89 → 未 strict 上板）
- [ ] **下一場**：flash 含 P0 韌體後短收，確認 CSV `deauth_tgt`／`seq_jump` 非全 0
- [ ] **下一場**：補 ARP／DEAUTH／可靠 SYN STOP；重跑 balance + train + ±WIDS 消融
- [ ] 與組員對齊評估協定後再比數字

### 中期（WIDS 補強）

- [x] 實作 P0：`deauth_targeted`、`seq_jump`（韌體 + `WINDOW_FEATURES` + 聚合 + collector）
- [ ] P1：unique_bssid 窗、EAPOL；更新特徵契約
- [x] 消融管線：±P0 WIDS、±HIDS（本場 P0 lift≈0，待新資料）
- [x] Collector：Serial standby

### 較長期（可選）

- [x] 第四攻擊腳本：`host/attacks/attack_auth_flood.sh`（label `AUTH_FLOOD`；收資料待 Phase C 實驗日）
- [x] `live_state` 帶 `ap_bssid`／`channel`（韌體 syslog → collector；`prepare_wifi.sh` 優先讀 channel）
- [ ] 韌體模組化
- [ ] 100 ms vs 250 ms 消融（同一特徵集）
- [ ] HIPS：等 FPR 明顯低於 ~10% 再考慮開啟

---

## 7. 跟組員溝通要點（可直接貼）

1. 你的無線特徵與模型數字很有價值，這塊我們想當 **感測／特徵參考標準**。  
2. 收集、多攻擊標註、Pi／Serial、訓練上板鏈路我們這邊較齊；目標是 **合成一條主線**，不是兩套正式結果並立。  
3. 合流方式：特徵進我們的 **100 ms 窗／syslog**，不是整包改 CSV 廣播。  
4. 對外故事：**multimodal（無線 + 主機）**；你的工作算強化無線面，不是「做錯去 WIDS」。

---

## 8. 相關文件

| 檔案 | 內容 |
|------|------|
| `note/compare_wids_vs_nids.md` | WIDS 定義、兩 repo 架構對照（含 Marp） |
| `note/lab_runbook.md` | 實驗日 Mode P/W/S 流程 |
| `note/note.md` | 架構、discovery、已知資料問題 |
| `README.md` | 快速上手 |
| 組員 `esp32_packet_monitor/` | sniffer／metrics／collect_dataset 參考實作 |

---

## 9. 下一實驗日待辦（寫給明天的自己）

1. **驗證 P0 欄位有進 CSV**（短 deauth 即可）。
2. **補一場短收**：多 NORMAL + ARP／DEAUTH；SYN 必須看到 STOP ACK。
3. 跑 `check_dataset_balance.py` → `analyze_and_train.py --plot [--strict-export]`。
4. 報告沿用 08-02 平衡場數字（披露 SYN 校正）；勿報舊灌水指標。
5. AUTH_FLOOD／HIPS 先擱置。

詳細節奏與 Mode P/S 指令見個人筆記 `note/private/phase_a_collection.md`、`note/private/phase_a_eval_20260802.md`（gitignore）。
