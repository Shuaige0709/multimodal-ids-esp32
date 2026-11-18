# Demo 防護總驗收

已完成 On／Off 的七階段驗收後，請改用 [最後一輪 PMF 確認與收案準則](demo_defense_final_check.md)，不必重跑本頁整套流程。

## 先做這兩步

Windows：先 Ctrl+C 關掉原本 UART collector 或 ESP-IDF monitor。USB 保持接著，在專案目錄執行：

```powershell
.\scripts\prepare_demo_defenses.ps1 -Mode On -FlashAndStart
```

會沿用你已確認的 gateway IP／MAC 與 **ESP32 所連的 2.4 GHz BSSID**，編譯、燒錄、啟動網頁及 UART 紀錄。預設 PMF 相容模式，避免目前 AP 不支援而連不上。不需要 Raspberry Pi。

等網頁出現「可正常通訊」，另開一個 PowerShell：

```powershell
.\scripts\print_arp_guard_targets.ps1 -FullDemo
```

把它印出的**整段**貼到 Kali 的專案目錄執行。它會直接帶好 IP、MAC、BSSID、channel，最後一行啟動總驗收。Kali 需更新這次的 scripts，已儲存測試 AP 的 Wi-Fi 連線，並裝有 dsniff、mdk4、aircrack-ng、python3-scapy。

流程約 10–15 分鐘：正常 30 秒 → 單向 ARP 45 秒 → 雙向 ARP 45 秒 → Probe、Beacon、Twin 各 30 秒 → Deauth → Disassoc 30 秒。每段之後自動觀察恢復 30 秒；Deauth 沿用既有五批定向發送。最後自動把 Kali 無線網卡切回 managed。不要同時另跑其他攻擊。

工具失敗會停止並指出階段，**工具退出成功不等於防護通過**。Kali 在 `data/demo_acceptance/時間/` 自動留下各段 log、開始／結束時間及退出碼。這是功能驗收，不混入模型訓練資料。

跑完再等 30 秒，Windows collector Ctrl+C。CSV、原始 `.csv.log`、自動匯出的 `.dashboard.json` 都會保留，不需要手動填 QC 或 manifest。把新檔案留在原處即可交由 agent 分析。

## 這次實際新增什麼

- **ARP 本機修復與鎖定**：只接受事先設定的可信任 gateway，在指定 AP／gateway 下作用。
- **限量 GARP（Gratuitous ARP，主動廣播自己的 IP／MAC）**：本機已鎖定，且連續兩次 ICMP 未回覆才觸發。每批最多 3 次、每次至少間隔 1 秒、批次起點至少相隔 30 秒、每次開機最多 12 次嘗試。廣播失敗也扣預算；收到回覆就取消剩餘批次；換網或斷線取消當批，但不補回預算。
- **通訊驗證**：持續測試 gateway ICMP；連續 3 次回覆才確認可達。先有失敗、在防護鎖定下恢復回覆，才顯示「通訊已恢復」。廣播送出只表示交給本機網路堆疊，不能當作路由器已接受。
- **Evil Twin 防護**：啟用時限制 station 連到設定的 BSSID，不跟隨其他同名 AP；因此也停止強制把無線電調回歷史 channel 11。BSSID 仍可偽造，這不是伺服器憑證或密碼學身分驗證。
- **Deauth／Disassoc**：保留既有重連退避和恢復時間記錄，增加 PMF Required 設定入口。只有 AP 支援 PMF 且成功建立要求 PMF 的連線，才可驗證其保護效果。
- **Probe／Beacon／Auth flood**：目前仍為偵測與維持服務的觀察項。沒有偽稱能從 station 阻止空中發射或抵銷頻道壅塞；不更改既有模型特徵或閾值。

網頁分開顯示「本機映射已鎖定」、「已廣播正確映射，等待驗證」和 gateway 回覆。Wi-Fi 已連線但驗證失敗時，主狀態會顯示「通訊未通過驗證」。

## 看什麼才算有幫助

- 單向 ARP：出現本機鎖定，攻擊期間 gateway 回覆能維持或恢復。
- 雙向 ARP：確認有 GARP 動作，接著觀察**攻擊仍持續時**是否恢復回覆；若只在停止攻擊後恢復，不能說 GARP 在攻擊中保住通訊。路由器可能忽略廣播，持續投毒也可能再覆寫它，這時應顯示驗證失敗。
- Twin：檢查實際連線 BSSID 一直是可信任 AP。既有 Twin 腳本主要產生同名 AP 訊號，沒有強制 station 重新選 AP，單靠這場不能證明成功阻止誘導連線。
- Probe／Beacon：看見告警、UART 持續、攻擊後恢復。這是可觀察性／持續運作測試，不是阻擋發射端的證據。
- Deauth／Disassoc：相容模式可能仍斷線，重點是正確記錄及自動恢復；Required 模式才另外測 PMF 防護。

## 要比較關閉防護

這輪 On 驗收完成後才需要做第二輪。先停 collector，再執行下面這條，接著重新產生 Kali 整段指令：

```powershell
.\scripts\prepare_demo_defenses.ps1 -Mode Off -FlashAndStart
```

Off 會關閉 ARP 修復、GARP 與可信任 BSSID 限制，但保留 ICMP、偵測與重連，PMF 仍是 Optional。它不是「完全無 PMF」的嚴格對照。

## AP 已確認支援 PMF 才選這個

```powershell
.\scripts\prepare_demo_defenses.ps1 -Mode On -Pmf Required -FlashAndStart
```

Required 會拒絕沒有 PMF 的 AP；若連不上，改回第一條 Optional 指令。網頁「要求 PMF 保護連線」表示設定政策，不表示已另外讀出協商狀態；仍須成功連線及攻擊驗收。

## 實作依據

- [Espressif PMF 設定](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/api-guides/wifi-security.html)：Required 只連 PMF-enabled AP。
- [Espressif lwIP etharp.h](https://github.com/espressif/esp-lwip/blob/2.2.0-esp/src/include/lwip/etharp.h)：使用本機介面的 gratuitous ARP，不偽造 gateway 身分。

目前完成的是程式、編譯及離線驗證；新 GARP 對這台路由器的效果仍以這次實機總驗收為準。
