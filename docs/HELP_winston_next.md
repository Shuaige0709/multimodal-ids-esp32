# 本週任務（Winston）：固定 AP sidecar 模型小實驗

> 目的：不要只短收一場。這次要回答「固定 AP 下的 AUTH / ARP sidecar 能不能訓練出有效模型」，並用 run-level holdout 檢查是否真的可用。  

## 0. 短收為什麼不夠

但短收不能證明模型有效，因為：

- train / test 如果都來自同一段錄影，模型可能只是學到時間順序或當下背景流量。
- AUTH / ARP 很容易受 AP、client isolation、連線狀態影響。
- `gw_flip` 是 cumulative，不能直接當 window feature。

所以這次任務要做 **多個 blocked trace + run-level holdout + 小模型報告**。

## 1. 要收什麼資料

使用最新韌體與 collector，CSV 需要有：

- `pred_attack`
- `pred_raw`
- `calib_thr`
- `win_pkts`
- `win_deauth`
- `win_probe`
- `win_beacon`
- `win_auth`
- `win_bssid`
- `win_twin`
- `win_rogue`
- `gw_mac`
- `gw_flip`

每場都要記：

- SSID / BSSID / channel。
- AP/client isolation 是否關閉。
- 攻擊 command。
- START / STOP time。
- 當時是否有人正常使用網路。



## 2. 最小資料量

至少收 6 場，理想 8-10 場。


| 類型                   | 場數  | 每場格式                                    | Label        |
| -------------------- | --- | --------------------------------------- | ------------ |
| fixed AP idle normal | 2   | `NORMAL 10-15 min`                      | `NONE`       |
| fixed AP normal use  | 1-2 | `NORMAL 10-15 min`，可看影片/瀏覽              | `NONE`       |
| `AUTH_FLOOD` blocked | 2-3 | `NORMAL 3m -> AUTH 60-90s -> NORMAL 3m` | `AUTH_FLOOD` |
| `ARP_SPOOF` blocked  | 2-3 | `NORMAL 3m -> ARP 60-90s -> NORMAL 3m`  | `ARP_SPOOF`  |


如果時間不夠，優先順序：

1. `AUTH_FLOOD` 2 場 + normal-only 2 場。
2. `ARP_SPOOF` 2 場。
3. normal-use 1 場。



## 3. Train / holdout 切法

不要用 random window split 當主結論。要用 **run-level split**：

```text
train:
  normal run 1
  AUTH run 1
  ARP run 1

holdout:
  normal run 2
  AUTH run 2
  ARP run 2
```

可以額外報 random split，但只能當 sanity check。

主結論看：

- holdout event-level detection。
- holdout normal false alarms。
- per-attack delay。
- feature importance / rule explainability。



## 4. 可訓練的模型範圍

先做輕量模型，不要做大深度模型。

推薦：

- rule baseline：`win_auth >= k`、`gw_mac_changed_this_window`、N-of-M hysteresis。
- shallow DecisionTree：max depth 2-4。
- shallow RandomForest：小樹數，只當 offline comparison。
- logistic regression：當簡單線性 baseline。

避免：

- LSTM / deep CNN。
- federated learning。
- 大型 autoencoder。
- 把模型直接轉成 `main/model.h`。



## 5. 特徵建議

不要直接用 cumulative `gw_flip >= 1` 當模型特徵。請先整理出 per-window 或 delta 特徵：


| Feature                      | 說明                                  |
| ---------------------------- | ----------------------------------- |
| `win_auth`                   | 100 ms window AUTH subtype count    |
| `auth_ratio`                 | `win_auth / max(win_pkts, 1)`       |
| `auth_burst_1s`              | 最近 1 s AUTH 總數                      |
| `gw_mac_changed_this_window` | 本窗 gateway MAC 是否和上一個有效 `gw_mac` 不同 |
| `new_gateway_mac_seen`       | 本場第一次看到新的 gateway MAC               |
| `gw_change_burst_5s`         | 最近 5 s gateway change 次數            |
| `win_deauth/probe`           | 控制變項，避免模型把 deauth/probe 誤當 AUTH/ARP |
| `win_pkts`                   | 只能輔助，避免模型只學總量                       |


如果沒有時間做新欄位，至少交 raw CSV，讓主線這邊補 feature engineering。

## 6. 成功標準

這次不是看 accuracy。請用以下判斷：


| 指標                       | 期待                                                    |
| ------------------------ | ----------------------------------------------------- |
| normal-only false alarms | 低，最好 10-20 min normal 沒有或極少 rising edge               |
| AUTH event detection     | holdout AUTH 至少 2/2 或 2/3 命中                          |
| ARP event detection      | holdout ARP 至少 2/2 或 2/3 命中                           |
| delay                    | 最好 < 2 s；ARP 可放寬但要說明                                  |
| feature importance       | 主要由 `win_auth` / gateway-change 類特徵解釋，不是只靠 `win_pkts` |
| run-level holdout        | 必須報；random split 不能當主結果                               |


如果 normal FPR 高，模型就算 attack recall 高也不能升級，只能寫成：

> fixed AP visibility evidence, not deployable sidecar gate.



## 7. 交回內容

請交回一個資料夾，至少包含：

```text
winston_sidecar_model_YYYYMMDD/
  raw/
    nids_dataset_....csv
  windows/
    nids_windows_....csv
  README.md
  results.md
  model_report.json  (可選)
```

`README.md` 要寫：

- 每場 stamp。
- 每場角色：normal / normal-use / AUTH / ARP。
- AP SSID / BSSID / channel。
- 攻擊 command。
- START / STOP time。
- 是否有 client isolation。
- 訓練/holdout 怎麼切。

`results.md` 要有：

- normal-only FPR / rising edges。
- AUTH holdout event detection。
- ARP holdout event detection。
- delay。
- feature importance 或 rule threshold。
- 結論：可升級 sidecar candidate / 只能 visibility / 失敗。



## 8. 不要做

- 不要只交一場短 CSV 然後說模型有效。
- 不要用 random window split 當主結論。
- 不要把 `gw_flip >= 1` 當 ARP 成功。
- 不要把不同 AP 混成一個 train baseline。
- 不要把 `hping --flood` 當 normal。
- 不要把模型 merge 到主線 `model.h`。



## 9. 給 Winston 的短版說法

```text
請你做固定 AP 的 AUTH/ARP sidecar 小模型實驗，不是只短收。

至少收 6 場，理想 8-10 場：
- normal-only 2 場，每場 10-15 min
- normal-use 1-2 場，每場 10-15 min
- AUTH_FLOOD blocked 2-3 場：NORMAL 3m -> AUTH 60-90s -> NORMAL 3m
- ARP_SPOOF blocked 2-3 場：NORMAL 3m -> ARP 60-90s -> NORMAL 3m

請用 run-level holdout，不要只 random split window。目標是看 holdout normal FPR、AUTH/ARP event detection、delay、feature importance。模型只當 sidecar/M2 candidate，不要改主線 model.h。
```

