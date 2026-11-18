# 競賽 demo 試跑檢查（2026-11-18 晚間）

## 更新後重跑：19:30:49 場次已完成主要流程

來源：[`COMPETITION_LIVE_20261118_193049.csv`](../data/raw/COMPETITION_LIVE_20261118_193049.csv) 與 [UART log](../data/raw/COMPETITION_LIVE_20261118_193049.csv.log)。檢查至約 19:37:21；collector 仍在寫入，以下以已完成的攻擊區間及恢復事件為準。網頁事件以相同 `DashboardState` 與 `parse_sd` 從原始 log 重建核對，沒有另開回放服務，也沒有更動原始資料。

### ARP：偵測、鎖定與持續通訊符合預期

- CSV 攻擊標註可見於 19:34:04.719–19:34:36.360，共 306 窗。此範圍是 collector 標註區間，不等同工具精確發包時長。
- 19:34:05.697 UART 記下一次 gateway 身分不符，觀察到的 MAC 為 Kali 的 `BC:30:7E:23:2D:64`。
- 19:34:05.713 記下 `action=locked repairs=1 err=0`，表示已成功修復並鎖定。
- 攻擊標註區間可見 28 筆閘道器探測，全部 `ok`；無 Wi-Fi 斷線，沒有 GARP 發送。此次單向 ARP 由本地鎖定維持了被量測的閘道器可達性，不需要觸發失聯後的限量 GARP。
- 正確展示說法：**偵測到 ARP 身分異常後，完成修復鎖定，攻擊期間持續收到閘道器回應。** 此場沒有先失聯再恢復，不能將其敘述為量測到一段 ARP 通訊中斷後的恢復；閘道器 ping 也不代表已驗證所有應用或外網服務。

### Deauth：斷線、重連、恢復符合預期

- CSV 標註區間約 19:34:47.522–19:35:08.457，共 196 窗；157 窗有最終無線告警。首次最終告警約在首個標註窗後 1.6 秒，僅為 collector 時間對齊下的近似延遲。
- 19:34:48.787 首次斷線，reason 7；後續 reason 7／202／205 屬於同一段失聯與重連過程。
- 重連嘗試共 6 次，退避由 500 ms、1 s、2 s 增至 4 s。
- 19:35:10.967 重新取得 `192.168.0.14`；從首次斷線算起約 **22.2 秒**。網頁狀態模型也將其合併成 **1 次斷線、6 次嘗試、已恢復**。
- 19:35:11.243 首次恢復後的閘道器探測成功，距 Got IP 約 0.28 秒；19:35:13.494 已連續收到 3 次成功回應，可供網頁確認通訊可用。
- 失聯時探測暫停，最後一次失聯前與第一次恢復後的探測相距約 22.57 秒。因此「探測無 timeout」不能解讀為 Deauth 期間仍可通訊。
- 這是**攻擊偵測及自動重連恢復成功**，不是 Deauth 被阻擋。此 AP 的 PMF 限制不因本次重跑而改變。

### 展示時要避免的誤解

1. **修復次數 2 不等於兩次 ARP 攻擊。** 第一次是 ARP 異常修復；Deauth 斷線時鎖定會釋放，恢復後程式依 `armed_after_reconnect` 重新套用鎖定，因而累計為 2。原始 log 只有一次 ARP mismatch。
2. **一波 Deauth 不等於多種攻擊。** 原始事件模型除 Deauth／Disassoc 外，還產生短暫 Probe 以及數段「無線異常」。前端會隱藏已結束且短於 1 秒的無線事件，但其中約 4.5 秒及 7.6 秒的「無線異常」仍可能出現在歷史。這與目前按每窗證據命名及事件分組有關，不應宣稱另外偵測到獨立攻擊。
3. **有擷取佇列丟棄，但 UART 持續。** 攻擊後 `qdrop=110`、`uartdrop=0`；沒有看到重啟或 panic。這說明洪泛下並非完整擷取，並未中斷本次失聯及恢復事件的記錄。

本場已足以驗證兩個主要現場 demo 流程，不必為此增加研究錄製。若要短時間改善競賽可讀性，優先調整「鎖定重新套用」的文字及同波攻擊的歷史分組，不必再調整偵測模型。

### 顯示修正已完成

- 新版顯示「ARP 異常修復 1 次 · 重連後恢復防護 1 次」，動作歷史也分別命名。晚接 collector、只看到既有鎖定而沒有異常事件時，不會把韌體累計值推定成新攻擊。
- 新增獨立 `display_events` 顯示分組：同一段實測斷線內，若已有 Deauth／Disassoc 證據，將其相關 Probe 與未分類無線紀錄合併。ARP、Twin、Beacon 不合併；只有斷線而沒有 Deauth 證據，也不自行命名成 Deauth。
- 用本場既有原始 log 核對：原始 6 筆事件完整保留，畫面為 1 筆 ARP＋1 筆 Deauth。合併資料包含 `source_ids` 與 `observed_types`，原始 `events`、CSV、告警判定及資料匯出仍可查核。
- 46 項回歸測試，以及本場資料的中文／英文、320／390／1280 px 瀏覽器檢查通過。沒有修改模型、韌體或新增攻擊錄製；重啟 Windows dashboard 後重新整理網頁即可套用。
- [PMF 以外的 Deauth 防禦研究與適用性](deauth_defense_feasibility_20261118.md)：確有替代研究，但未找到能以目前公開 API 直接加入的可靠阻斷方案。

---

## 結論

**後續修正：** 下文 IP 不一致是當時的診斷。新版 Kali 腳本已改為先驗證即時資料、ESP32 MAC、AP 與防護狀態，再自動取得 DHCP IP；不再要求將裝置固定為 `.10` 或 `.14`。閘道器及 AP 的信任設定仍需在換網路時事前配置。以下「固定 DHCP／同步 ESP32 IP」步驟已由自動取得取代，不需照做。

這次最新 UART 檔案目前呈現正常監控，尚無足夠證據驗證 ARP 修復或 Deauth 的斷線、重連、恢復。不能把網頁上的早晨事件算成本次試跑成果。這是展示啟動流程與資料來源問題，尚未證明偵測或防護功能失效。

## 本次實際資料

- 原始檔：[`COMPETITION_LIVE_20261118_180837.csv`](../data/raw/COMPETITION_LIVE_20261118_180837.csv) 與 [主控台 log](../data/raw/COMPETITION_LIVE_20261118_180837.csv.log)。
- 檢查範圍：18:08:38.835862–18:16:52.119621，共 4,787 筆視窗；檔案當時仍持續寫入，這是檢查快照，不是整場最終總數。
- 全部 `label=0`、`attack_type=NONE`、`pred_attack=0`；`deauth_tgt`、`gw_flip`、`reconn` 也都為 0。
- 主控台擷取到 439 筆通訊探測結果，全部 `ok`；最後裝置累計為 444/444。兩者分別是本檔可見紀錄與裝置累計，不應混為同一分母。
- ARP 防護開啟，狀態持續為 `watch`、`repairs=0`；沒有修復事件或 GARP 發送紀錄。
- 沒有 Wi-Fi 斷線、重連或取得 IP 的事件。因此不能從本檔計算 Deauth 恢復時間。
- 少量未定向 deauth 訊框與背景 probe 不等於預定攻擊已經執行。沒有 START/STOP 標籤也不能單獨證明攻擊未執行；此處是標籤、射頻證據、主機影響三者均未呈現預定流程。

## 會阻擋競賽展示的兩個問題

1. **網頁網址指向舊回放。** 檢查 `http://localhost:8080/api/status` 時，回傳 `presentation.mode=recorded`、`finished=true`，來源為 `DEFENSE_On_Optional_20261118_113635.csv.log`。其中 ARP 修復與兩段恢復事件屬於早晨資料，不能代表本次即時偵測。Kali 的 readiness check 會拒絕此來源，這項檢查應保留。
2. **實際 IP 與設定不一致。** 最新 UART 的 `[ARP_GUARD]` 明確顯示 ESP32 IP 為 `192.168.0.14`，但 Windows/Kali 共用的 [`network.json`](../demo/competition/network.json) 仍指定 `192.168.0.10`。即使解決舊回放問題，Kali 仍會拒絕不符的目標。競賽前應在自用 AP 將 ESP32 MAC `B0:CB:D8:C9:92:00` 保留固定 DHCP 位址，並讓兩台電腦的 profile 與實際位址一致。準備腳本不會替 AP 設定 DHCP 保留。

使用者此次貼回的是 Windows `prepare_competition_demo.ps1` 準備指令，尚未取得 Kali 終端的 READY／Not ready／Attack running 輸出；不能推定 Kali 攻擊工具已跑完。

## 已修正的啟動防呆

- [`demo_dashboard.py`](../scripts/demo_dashboard.py)：Windows 使用獨占 HTTP 埠，避免舊回放與新 collector 共用網址。
- [`prepare_competition_demo.ps1`](../scripts/prepare_competition_demo.ps1)：在變更設定或燒錄前檢查埠；若已有回放或其他服務，明確停止並指出原因，不自動終止程序。
- 加入第二個服務不得共用埠的回歸測試；41 項測試通過。另以臨時回放伺服器驗證 PowerShell 在開啟序列埠或燒錄前確實停止；DryRun 與語法檢查也通過。
- 本次沒有燒錄、改動 AP、執行攻擊或終止現有服務。已執行中的舊程式必須關閉重啟，才會套用修正。IP profile 尚未擅自改成 DHCP 暫時取得的位址。

## 下一次展示前最少確認

1. 在舊回放及舊 collector 終端按 `Ctrl+C`；collector 會保存結束快照。單純關掉瀏覽器不會釋放網頁埠或 COM。
2. 確認 ESP32 的保留 IP，讓 Windows 與 Kali 的 `network.json` 一致；避免拿 `.10` 的攻擊設定打 `.14`。
3. Windows 重新啟動即時 dashboard。現有韌體已開啟防護，僅修正 Windows 程式不需重燒，可用 `prepare_competition_demo.ps1 -UseExistingFirmware`。
4. Kali 執行 `sudo python3 host/attacks/competition_demo.py`，必須看到 READY 才按 Enter；若出現 Not ready，保留錯誤文字，不將未執行的攻擊當成驗收完成。
5. 完成後在 Windows 按 `Ctrl+C` 保存紀錄，再核對本場 ARP 修復、通訊探測，以及 Deauth 的斷線到恢復事件。

這是既有現場 demo 的流程修正，不需增加研究用資料收集。先前防護驗收的量測與 PMF 限制仍參照 [`demo_acceptance_results_20261118.md`](demo_acceptance_results_20261118.md)，不可與本次混算。
