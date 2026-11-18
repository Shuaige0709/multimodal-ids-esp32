# 競賽 demo 試跑檢查（2026-11-18 晚間）

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
