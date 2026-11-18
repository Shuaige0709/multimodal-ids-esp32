# 最後一輪防護確認：PMF

這階段到此收斂，不再重跑整套或增加攻擊種類。只確認 AP 的 PMF 宣告；有支援才補 Deauth、Disassoc。資料仍由 Windows UART collector 保存，不需要 Pi、不填人工表格。

## 1. 還不用燒錄，先查 AP

Kali 先更新這次已推送的程式：

```bash
git pull --ff-only origin main
```

Windows 專案終端執行：

```powershell
.\scripts\print_arp_guard_targets.ps1 -CheckPmf
```

它會從本機可信任設定讀取正確的 **ESP32 2.4 GHz BSSID**，印出一條 Kali 指令。整條貼到 Kali 即可；會自動切回 managed、掃描指定 AP，結果與原始掃描輸出留在 `data/demo_acceptance/pmf_scan_時間/`。

結果判讀：

- `capable`：AP 廣播的 RSN 資訊含 MFPC；目前宣告支援 PMF，可以做第 2 步。
- `required`：AP 同時宣告 MFPC／MFPR，要求 PMF，可以做第 2 步。
- `not_advertised`：有效 RSN capabilities 未設 PMF 支援位元。代表這個 BSSID **目前沒有宣告**，不等於硬體永遠不支援。可在路由器 Wi-Fi 安全性頁找「PMF／802.11w／Protected Management Frames」，若能直接開 Optional／Capable，再掃一次；沒有選項就停止，不為 demo 換網路或買 AP。
- `unknown`：未找到指定 AP、掃描失敗或 RSN 資料不完整／矛盾，不能當成「不支援」。確認 Kali 網卡已連入 VM、AP 開著，最多重試一次；仍無法確定就記為未驗證，結束此階段。

掃描判讀來自 AP 宣告，並不是 ESP32 已協商使用 PMF 的證明。只看 SSID、WPA2 名稱或「802.11n」無法判斷；必須看這個 BSSID 的 RSN 資訊。

## 2. AP 有支援才燒 Required

先 Ctrl+C 關掉舊 collector／monitor，USB 保持接著：

```powershell
.\scripts\prepare_demo_defenses.ps1 -Mode On -Pmf Required -FlashAndStart
```

這次同時啟用 ARP 修復、限量 GARP、可信任 BSSID 限制、最低 WPA2 安全等級及 PMF Required。最低 WPA2 會拒絕 open／WEP／舊 WPA 的降級連線；這是已設定為 WPA2/WPA3 Personal 的本專題部署設定。

等約 30 秒。若網頁仍沒有顯示設備已連線及閘道器可回覆，不執行攻擊。Required 無法連線可能涉及 AP 設定、相容性、認證或其他連線問題，不能只憑失敗就斷言 AP 硬體不支援 PMF。這輪不再繼續除錯，直接回復：

```powershell
.\scripts\prepare_demo_defenses.ps1 -Mode On -Pmf Optional -FlashAndStart
```

留下 Required 的失敗日誌，PMF 記為未完成驗證，停止此階段。

## 3. 只跑兩個攻擊

Required 成功連線、gateway 可回覆後，另開 PowerShell：

```powershell
.\scripts\print_arp_guard_targets.ps1 -PmfOnly
```

整段輸出貼到 Kali。腳本會確認 Windows 回報的是新鮮的 Required-mode 連線，再產生指令；依序正常觀察 30 秒 → Deauth → 恢復觀察 30 秒 → Disassoc 30 秒 → 恢復觀察 30 秒，自動切換網卡模式並最後還原 managed。沿用與 Optional 輪相同的攻擊工具，不重跑 ARP、Probe、Beacon、Twin。

Kali 工具失敗即停止，不能當作 PMF 擋住攻擊。跑完 Windows 再等 30 秒才 Ctrl+C，CSV、raw log、dashboard JSON 自動保存。

## 結果怎麼收案

- **PMF 通過**：Required 已成功建立連線，兩個攻擊工具正常發送，且板子實際觀察到對應無線證據；攻擊期間沒有斷線，gateway 回覆持續，才支持「此設定下抵抗本次偽造 Deauth／Disassoc」。這是協定層預先保護，不是決策樹看到告警後才啟動。
- **只在停止攻擊後恢復**：記為自動恢復成功，不能算攻擊期間保護成功。
- **工具成功但沒有板端無線證據**：無法把未斷線歸因於 PMF，記為未確認，不為湊成功繼續擴大收集。
- **PMF 無法測／仍失敗**：如實收案。目前明確成功的防護只有單向 ARP；其餘呈現偵測、服務持續性或自動恢復。

## 其餘防護的最終界線

- 單向 ARP：現有 ON 46/46 次 gateway 回覆、OFF 4/31 次，支持本場防護有效。
- 雙向 ARP：ON 4/31 次回覆、OFF 2/30 次；ON 送出 GARP，但尚未保住通訊。不再加大廣播量，持續回程污染需要路由器端配合。這裡只驗證到 gateway 的 ICMP，不代表所有應用流量安全。
- Evil Twin：BSSID 限制與最低 WPA2 提供預防，但現有同名 AP 測試沒有證明成功阻擋重新選 AP 的誘導。BSSID 可偽造；不能宣稱完整的惡意 AP 身分驗證。
- Probe／Beacon flood：兩輪攻擊區間 gateway 回覆都正常。能展示偵測與持續運作，沒有防護開關的增益證據；單一 station 不能停止別人的發射或取回被佔用的空中時間。
- Deauth／Disassoc：Optional 的 ON／OFF 兩輪均斷線；PMF 是最後待驗證項目。PMF 不保證抵抗射頻干擾或所有管理訊框洪水。
- Auth flood：未列入這輪防護成功主張，不延伸新實作或新驗收。

上述統計以 CSV 的標註區間粗對齊 UART 接收時間；首個 ARP 階段依腳本順序視為單向，第二個為雙向。它們是功能驗收的觀測，不是多次獨立重複實驗的效果估計。

收案後轉往 demo 敘事、展示流程與備援錄影，不再因防護種類不足延長這輪工作。

依據：[Espressif PMF Required 行為](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/api-guides/wifi-security.html)、[Linux iw 的 RSN capabilities 輸出](https://kernel.googlesource.com/pub/scm/linux/kernel/git/jberg/iw/+/d90618809e06e123241f57efdb7039a7a8a43d58/scan.c)。
