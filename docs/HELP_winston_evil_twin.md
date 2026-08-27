# 本週任務（Winston）：固定 AP · evil twin 可見性

## 目標

量 **同 SSID、第二顆 BSSID** 的 evil twin，在你們板上的 `win_bssid` 看不看得見。  
順便量安靜時 `win_bssid` 的底（鄰居 AP 會不會本來就不只 1）。

Evil twin ≠ beacon flood：一顆假 AP、名字跟真的一樣、channel 跟真 AP 相同。亂數 beacon 風暴當**對照**可以，不能拿來充 twin。

## 本週量

| 種類 | 場次 | 用意 |
|------|------|------|
| 純 IDLE | **≥2**（可不同時段，例如下午 / 晚上） | 鄰居 BSSID 底噪 |
| 標籤 EVIL_TWIN | **≥4**（至少兩天；時長不要全相同） | 主閘門 |
| 亂數 beacon flood 對照 | **≥1** | 證明 twin 不是「封包變多」 |
| 短寫 | 1 份表 | idle vs twin vs flood 的 `win_bssid` / `win_pkts` |


## 過關條件

- Twin 段 `win_bssid` 比**同檔 idle** 高 → 看得見  
- airodump 看得到假 BSSID、板上沒動 → 空氣有、感測器沒吃到  
- tot 暴衝、BSSID 一次跳很多 → 當成 flood，不當 twin  


## 交回

每場：環境（SSID / BSSID / CH）+ 檔名 + idle/twin 的 `win_bssid` 中位與 max + 一句結論。  
