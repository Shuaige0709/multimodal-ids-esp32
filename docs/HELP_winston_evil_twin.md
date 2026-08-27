# 本週任務（Winston）：固定 AP · evil twin 可見性

## 目標

量 **同 SSID、第二顆 BSSID** 的 evil twin，在板上能不能跟安靜時分開。  
安靜時鄰居 AP 本來就不只 1 顆是正常的；主訊號是「我們的 SSID、但不是連上的那顆 AP」。

Evil twin ≠ beacon flood：一顆假 AP、名字跟真的一樣、channel 跟真 AP 相同。亂數 beacon 風暴當**對照**可以，不能拿來充 twin。

## 本週量

| 種類 | 場次 | 用意 |
|------|------|------|
| 純 IDLE | **≥2**（可不同時段，例如下午 / 晚上） | 鄰居底噪 |
| 標籤 EVIL_TWIN | **≥4**（至少兩天；時長不要全相同） | 主閘門 |
| 亂數 beacon flood 對照 | **≥1** | 證明 twin 不是「封包變多」 |
| 短寫 | 1 份表 | idle vs twin vs flood 的 `win_twin` / `win_rogue` / `win_bssid` / `win_pkts` |


## 過關條件

CSV 若有 `win_twin` / `win_rogue`（新韌體）：

- idle 的 `win_twin` 接近 **0**，twin 段 **≥ 1** → 看得見  
- twin 段 `win_rogue` 出現 1（假 MAC `02:13:37:00:00:01`）當實驗室對照  

只有 `win_bssid`、沒有 `win_twin` 的舊檔：twin 段 `win_bssid` 比**同檔 idle** 高才算。固定 AP 鄰居少時 unique count 可能仍夠用。

- airodump 看得到假 BSSID、板上沒動 → 空氣有、感測器沒吃到  
- tot 暴衝、BSSID 一次跳很多 → 當成 flood，不當 twin  


## 交回

每場：環境（SSID / BSSID / CH）+ 檔名 + idle/twin 的 `win_twin`（有的話）與 `win_bssid` 中位與 max + 一句結論。  
