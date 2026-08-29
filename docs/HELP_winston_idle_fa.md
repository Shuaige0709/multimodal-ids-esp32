# 本週任務（Winston）：固定 AP · IDLE 誤報、busy 空氣、分檔 SYN

Evil twin 在熱點上已過關，**不必再收 twin**。這週在你們固定 AP 上多收三類（都走我們這套 collector／`win_pkts`）：

1. 安靜時燈誤亮幾次
2. 兩台電腦經 AP 互傳時，空中 tot 有沒有比 idle 高
3. 打板子 HTTP 的 SYN 要分慢／中／快，不能跟 busy 用同一種 `--flood`

燒有 `win_twin` 的韌體（畫面有 `twin=`）。樹／閘門不要改。關 AP isolation。

## 本週量


| 種類         | 場次                               | label       | 用意                         |
| ---------- | -------------------------------- | ----------- | -------------------------- |
| 長 IDLE     | **≥3**（不同時段，各 15–20 min）         | 0           | 誤亮次數；`win_twin` 應一直 ≈0     |
| iperf busy | **≥2**（TCP 一場、UDP 一場，各 8–10 min） | **0**       | 兩台 STA 互打，**不要**打 ESP32    |
| 分檔 SYN     | **≥3**（慢／中／快各約 60 s，中間 idle）     | `SYN_FLOOD` | 和 busy 分開；快檔可以 flood，慢／中不要 |


不要：evil twin、beacon flood、再打 deauth／probe、把 `hping --flood` 標成 NORMAL。

瀏覽／影片／多 STA 那些 busy 產生器是 HaoHao 在試，這裡不必重複四種。

## 過關條件

- IDLE：寫時長、燈從滅到亮幾次 
- iperf：`win_pkts` 中位對**同日 idle**；有抬或沒抬都算交回  
- SYN：三檔都有 START/STOP；慢檔 tot／燈不要和快檔長一樣才有「分檔」意義  
- 燈亮不算 busy 成功

## 交回

填一張表即可：


| 檔名                   | 種類        | 時長     | `win_pkts` 中位／max | 燈 0→1 次數 | `win_twin` 中位 | 備註        |
| -------------------- | --------- | ------ | ----------------- | -------- | ------------- | --------- |
| `nids_dataset_….csv` | IDLE 下午   | 18 min |                   |          |               | SSID / ch |
|                      | iperf TCP |        | vs idle：          |          |               |           |
|                      | SYN 中     | 60 s   |                   |          |               |           |


