# 本週任務（HaoHao）：固定 AP 上的 busy NORMAL

可用 packet_monitor / Guard，不必改 nids 樹上的特徵或重訓。

## 目標

找出一種 **BUSY 但標成 NORMAL** 的收法：空氣上的密度／封包數要比 idle **明顯高**，且不要跟 SYN `--flood` 長一樣。

熱點上 YouTube 4K 空中幾乎看不見；先前 unlabeled `hping3 --flood` 當 busy，會和 SYN 攻擊撞形。固定 AP 比較有機會看到 STA 流量，因此需要可重複的產生方式。

## 本週量

| 種類 | 場次 | 用意 |
|------|------|------|
| 安靜 IDLE | **≥2**（可不同時段） | 底 |
| 候選 busy（label 0） | **≥4 種產生方式**，每種至少一場 | 瀏覽、影片、iperf、多 STA 等 |
| 反例：對板子 `hping --flood` | **≥1** | 和「真的 busy」差在哪 |
| 短寫 | 1 | 哪幾種空氣有抬、哪幾種沒有、下次 busy NORMAL 用哪一種 |

每場記錄：負載怎麼產生、誰連誰、`total_pkt`／密度（或 `win_pkts`）相對 idle 的中位與 max。有 `unique_bssid_window` 可一併寫；本週主問題是 busy 怎麼做。

## 過關條件

- 至少一種候選：空氣計數明顯高於同 AP 的 idle，且不是 flood 那種平滑高 tot
- 能對照熱點看不見、固定 AP 上看不看得見
- hping 反例有數字，不當成功 busy
- 亂數 beacon flood 不是 busy NORMAL

## 交回

產生方式清單 + 每場檔名與 idle/busy 統計 + 建議下一場正式 busy 用哪一種。大檔走雲端／USB。
