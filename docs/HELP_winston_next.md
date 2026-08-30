# 本週任務（Winston）：固定 AP normal baseline

> 目的：不要再重錄 ARP/AUTH。你之前固定 AP 的 ARP/AUTH visibility 已經夠用。這次只補「正常狀態下 sidecar 和燈會不會自己亂跳」。

## 要做什麼

使用最新韌體與 collector，CSV 需要有：

- `pred_attack`
- `pred_raw`
- `calib_thr`
- `win_deauth`
- `win_probe`
- `win_beacon`
- `win_auth`
- `win_twin`
- `win_rogue`
- `gw_mac`
- `gw_flip`

## 場次

| 種類 | 時長 | Label | 做法 |
|------|------|-------|------|
| 固定 AP idle / normal-only | 20-30 min | 0 / `NONE` | 不跑任何攻擊，讓 AP 正常待機 |
| 固定 AP normal use | 20-30 min，可選 | 0 / `NONE` | 家中正常上網、影片、瀏覽都可以，記誰在用 |
| positive control | 可選，1 min | 攻擊 label | 只在你想確認流程時跑短 deauth 或 probe；不是必要 |

## 不要做

- 不要重跑 ARP/AUTH。之前已經有可見性結果。
- 不要用 `hping --flood` 當 normal。
- 不要改模型、不重訓、不 merge branch。
- 不要用燈亮當 busy 成功；這次是 normal baseline。

## 交回

請回傳：

| 欄位 | 內容 |
|------|------|
| raw CSV | `data/raw/nids_dataset_....csv` |
| AP | SSID / BSSID / channel |
| isolation | AP/client isolation 是否關閉 |
| 場景 | idle / normal use |
| 時長 | 幾分鐘 |
| 當時網路使用 | 沒人用 / 影片 / 瀏覽 / 多裝置 |
| 簡單數字 | `win_pkts` 中位/max、`pred_attack` 次數、`win_auth`/`win_twin` 是否非 0、`gw_flip` 是否增加 |

## 為什麼要這樣做

固定 AP ARP/AUTH 已經證明「攻擊時訊號看得見」。現在缺的是反方向：

> 正常狀態下，這些 sidecar 會不會自己出現，造成 false positive？

如果 normal-only 很乾淨，ARP/AUTH/twin 才有資格當下一版 sidecar candidate。若 normal-only 本來就亂跳，就只能寫成 visibility evidence，不能接 evidence gate。
