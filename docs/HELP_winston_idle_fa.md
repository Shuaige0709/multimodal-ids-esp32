# 本週任務（Winston）：固定 AP · 長 IDLE 誤報 + 一種 busy

Evil twin 在熱點上已用 `win_twin` 過關，**不必再收四場 twin**。這週改量兩件板上還缺的：安靜時燈多久誤亮一次、這顆 AP 上 busy 空中看不看得見。

燒有 `win_twin` 的韌體（collector 畫面有 `twin=`）。樹／閘門不要改。

## 本週量

| 種類 | 場次 | 用意 |
|------|------|------|
| 長 IDLE | **≥2**（例如下午／晚上各 15–20 min，label 0） | 安靜 rising-edge 誤報；順手看 `win_twin` 是否一直 ≈0 |
| Busy（label **0**） | **≥1**：兩台 STA 經 AP `iperf3` 互打，**不要**打 ESP32 | tot 有沒有比同 AP idle 高 |
| 短寫 | 1 | IDLE 誤亮次數 + idle vs iperf 的 `win_pkts` 中位／max |

不要：evil twin、beacon flood、deauth/probe 煙測、`hping --flood` 當 busy（那是 HaoHao 的反例）。

## 過關條件

- 每場 IDLE：時長、`pred_attack` 從 0→1 幾次、`win_twin` 中位  
- iperf 場：tot 中位相對 **同檔或同日 idle** 有抬 → 這顆 AP 空氣看得到 busy；沒抬也寫，當 sensor gap  
- 燈不算 busy 過關  

## 交回

環境（SSID / BSSID / CH）+ 檔名 + 上表數字 + 一句結論。  
