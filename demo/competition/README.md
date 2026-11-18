# 五分鐘競賽：五張英文投影片＋真正的現場攻擊

## 檔案入口

- [五張簡報 PDF](slides/competition_demo.pdf)：16:9、白底、簡約英文，沿用海報／報告架構圖與結果圖。
- [LaTeX 原始檔](slides/competition_demo.tex) 與 [重編譯腳本](slides/build.ps1)。需要 Windows Segoe UI 與 XeLaTeX；原圖副本已包含於 assets。
- [英文講稿與兩分鐘問答](speaker_notes_en.md)：包含切換網頁的時機及現場未成功時的說法。
- [固定網路設定](network.json)：Windows 和 Kali 共同讀取，不需每次 export IP／MAC。
- 已完成的 [防護驗收結果](../../docs/demo_acceptance_results_20261118.md)。

正式流程完全使用現場攻擊與即時 USB 資料，不啟動回放。設定：先講前三張約 1 分 50 秒 → 第四張切至 live dashboard、兩個現場攻擊 → 約 4 分 15 秒回第五張 → 5 分鐘結束，另留 2 分鐘問答。

## 前置準備：一次設定，現場不改參數

這套預設沿用已驗證的 AP：SSID `302`、2.4 GHz BSSID `68:02:B8:BB:AF:57`、channel 11；ESP32 `192.168.0.10`／`B0:CB:D8:C9:92:00`；gateway `192.168.0.1`／`68:02:B8:BB:EC:D4`；Windows VMnet1 `192.168.124.1`，Kali USB 無線介面 wlan0，ESP32 COM3。

競賽使用自有／獲授權 AP，先把其 2.4 GHz 頻道固定為 11，並在 DHCP 預約 ESP32 MAC 對應 `.10`，避免當天換 IP。Windows 與手機可連同一台 AP 的 5 GHz，讓定向 2.4 GHz 攻擊較不易中斷展示畫面；這不保證不受共用 AP 負載影響。USB 線必須接著。

如果固定值有變，**事前只改 network.json**。AP 名稱與密碼仍需和韌體既有 `main/net_config.h` 一致；腳本不修改或公開密碼。Kali 事前儲存 SSID 302 的連線密碼、確認 USB 網卡交給 VM、VMnet1／host-only 路徑可用。網頁 HTTP 8080 與標註 UDP 10000 必須能從 Kali 到 Windows，沿用先前驗收的防火牆設定，不自動放寬防火牆。

## Windows：一個指令完成燒錄、英文網頁與 collector

關掉舊 monitor／collector／回放服務。在專案目錄：

```powershell
.\scripts\prepare_competition_demo.ps1
```

預設會套用正確的可信任 gateway 與 BSSID、啟用 ARP 防護與 PMF Optional、編譯並燒錄，再開啟 live USB collector 和英文網頁。這會重新啟動 ESP32，清除上一輪 ARP 鎖定，確保第一個攻擊仍有新的身分變化可觀察。保持該終端開著。

未連板子的純流程檢查：

```powershell
.\scripts\prepare_competition_demo.ps1 -DryRun
```

若已燒好同一個 On／Optional 版本、也已手動重啟，可加 `-UseExistingFirmware`，略過 build／flash。這不是軟體重置 ARP 鎖定的指令；Kali 會檢查是否已鎖定，避免重複展示時沒有新告警。

沒有改模型、沒有新增攻擊分類。網頁自動用英文開啟；手機可開 `http://電腦Wi-Fi-IP:8080/?lang=en`。固定網路值在前置階段驗證，上台不再查位址。

## Kali：一個指令完成準備並停在待命提示

確保已取得這次更新的程式，在專案目錄：

```bash
sudo python3 host/attacks/competition_demo.py
```

需要既有 `dsniff`／`aircrack-ng`、iw、ip、nmcli、timeout、Python 3。只執行這兩個攻擊，不要求 mdk4／scapy。

程式會恢復 managed 模式、檢查 Kali 連到正確 SSID，並從 Windows API 驗證：即時 USB 資料、ESP32 的 IP／MAC／channel／BSSID、防護 On、可信任 AP 綁定 On、正常的路由器回覆，以及本次開機還沒有 ARP 鎖定。回放頁面、資料過期或錯誤設定會拒絕開始。

出現 `READY` 就停在待命畫面，**不會自動發動攻擊**。這時可開始五分鐘報告；不用再複製貼上指令。

1. 切到網頁，Kali 按 **Enter**：啟動單向 ARP；預設 25 秒後自動停止，期間再按 Enter 可提前停止。
2. 程式自動切換 monitor 模式，停在第二個提示。配合講稿說明接下來要攻擊無線連線；模式切換時間取決於網卡／NetworkManager，不保證零等待。
3. 第二次按 **Enter**：啟動定向 Deauth，沿用原腳本、縮至 3 批；工具自行結束，期間再按 Enter 可提前停止。這是批次限制，不宣稱精確固定秒數。
4. 最多觀察 45 秒的實際重連與路由器回覆；未恢復就如實顯示未確認，不捏造完成。若時間不夠，Ctrl+C 停止，回第五張講結論。
5. 結束／取消時清理本程式啟動的攻擊 process group、補送 STOP 標註、還原原先 IP forwarding，並把網卡切回 managed。不要同時另跑其他攻擊腳本。

純流程檢查，不碰網卡、不送攻擊、也不連 API：

```bash
python3 host/attacks/competition_demo.py --dry-run
```

## 展示時要看什麼

- **ARP**：新的 ARP 告警與鎖定動作；攻擊仍持續時的路由器回覆。不要拿停止攻擊後自然恢復當成阻擋成功。
- **Deauth**：無線告警、實際斷線、重連狀態與最終中斷時長。這是恢復展示，不是聲稱 Deauth 已被阻擋。
- 單向 ARP 若防護很快，可能完全沒有可見 timeout；這是維持通訊，不必刻意製造斷線來演「修復」。
- 目前防護開關是編譯設定，這輪現場只跑 On。Off 對照使用已完成的研究數據，不在五分鐘內重新燒錄。
- 手機與 OLED 是輔助；大螢幕以網頁為主。USB 是呈現資料的通道，分類與 ARP 修復在 ESP32 上。

## 重複展示與失敗處理

第一個 ARP 已成功鎖定後，不直接再跑第二次期待同樣的新告警。先停止攻擊，確認網路正常，再重啟 ESP32。collector 保持開著會繼續接收；等連線與路由器回覆恢復後，再啟動 Kali 程式。

如果當場工具失敗、不出警報或未恢復，不切換回放冒充成功，也不連續重試耗盡時間。依英文講稿如實描述，回簡報用已完成的實驗結果解釋。這是展示流程，不要求新增研究資料或再做一套驗收。

本次只做程式乾跑、狀態防呆與文件檢查；沒有替你執行實體攻擊、燒錄或重新錄製。3 批 Deauth 的現場耗時與當天恢復速度仍取決於工具及網路，不是事先保證的展示成果。
