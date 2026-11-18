# 手機即時展示網頁

ESP32 用 USB/UART 傳送資料給 Windows；Windows 同時寫 CSV、原始主控台日誌，並提供網頁給手機。偵測仍在 ESP32 執行。網頁不需要 APK、雲端或 Raspberry Pi，首次加入每秒連線狀態回報時需要更新韌體；之後開啟網頁不必重新燒錄。

## 開始展示

1. ESP32 接 USB。先停止舊的 UART collector 與 ESP-IDF monitor，COM3 只能由一個程式讀取。
2. 在專題目錄的 PowerShell 貼上：

```powershell
cd C:\Users\yanwe\OneDrive\Desktop\Projects\espidf\nids_esp32_project
.\scripts\start_demo_dashboard.ps1
```

預設 COM3、網頁 8080。若埠號改變：

```powershell
.\scripts\start_demo_dashboard.ps1 -Port COM4 -WebPort 8080
```

終端會列出電腦與手機網址。電腦先開 `http://localhost:8080`；手機連到電腦所在區域網路，開終端列出的 **Wi-Fi 網卡**網址。不要填 ESP32 的 IP，也不要選 Kali VMnet 或 VPN 位址。此頁不需要網際網路，頁面字型與資源都在本機。

首次連入若 Windows 防火牆詢問，允許 Python 在目前的私人展示網路接受連線。電腦可看、手機不能看時，先確認手機與電腦同網段、AP 未啟用 client isolation；需要時以系統管理員 PowerShell 加入僅私人網路的規則：

```powershell
New-NetFirewallRule -DisplayName 'ESP32 IDS Demo 8080' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 -Profile Private -RemoteAddress LocalSubnet
```

開啟後保留終端，Ctrl+C 結束。現有攻擊指令可繼續使用，START/STOP 標籤仍由原 collector 在 UDP 10000 接收；**不需再開另一個 collector**。CSV 與 `.csv.log` 一樣儲存在 `data/raw/`，不覆寫舊場次。

## 斷線與恢復展示

新版首頁呈現「斷線 → 重連中 → 已恢復」三階段，旁邊顯示持續時間。韌體每次實際呼叫 Wi-Fi 連線 API 時，輸出 `[NIDS_RECONNECT] attempt`，網頁才會增加重連嘗試次數；偵測模型與原本重連退避策略不變。

- **斷線**：收到斷線事件即開始計時；多次 reason code 與重試不會重設起點。
- **重連中**：收到實際重連請求紀錄，顯示嘗試次數。
- **已恢復**：收到取得 IP／已連線回報才結束計時，顯示 8 秒恢復提示，並將完成事件保留在連線紀錄中。
- **資料中斷**：超過 5 秒無新連線回報、USB 中斷或板子重啟時，不繼續宣稱正在恢復。若中間缺少紀錄，該段標為「未確認恢復」，不產生完整恢復時間。
- **中途加入**：只看到已斷線狀態、沒有實際斷線起點時，時間以 `≥` 標示已觀測的最低長度。

計時使用電腦收到 UART 訊息的單調時鐘；這是展示用觀測時間，並非無線協定層精密延遲量測。連線恢復不代表攻擊已被阻擋。

驗收：正常頁面 → 在自己的測試網路製造斷線 → 觀察重連次數與計時 → 恢復 AP／停止攻擊 → 確認「已恢復」及歷史時間固定。USB 保持連到電腦，手機到電腦的網路也要維持可用。

## 介面設計

依 `landing-page-design` skill 的字級、間距、字型與狀態規範重整，受眾為競賽評審與設備使用者。採簡潔的設備監控介面：大字狀態、單一恢復區、細分隔線事件紀錄。首頁移除開發與評估說明，這些內容集中在本文件。由於是操作介面，不加入行銷用 FAQ、口號、推薦見證或註冊區塊。

參考 [Uptime Kuma](https://github.com/louislam/uptime-kuma) 的狀態及事件歷程呈現；本機附帶 [Geist](https://vercel.com/font) 字型與授權，中文使用系統可用中文字型。無需外部 CDN。ARP 自動防護與通訊驗證另見 [ARP 開關對照手冊](arp_guard_test_runbook.md)，需要可信任網路設定及新版韌體。

## 評審會看到什麼

- **目前狀態**：監控中、偵測到異常、等待資料、資料過期或 UART 中斷。
- **攻擊類型**：ARP 身分異常、Beacon Flood、Deauth / Disassoc、Evil Twin、Probe Flood，支援同時出現多個告警來源。無明確類別時顯示無線異常。
- **ESP32 Wi-Fi 狀態**：依板端 `WiFi disconnected`、`Got IP` 日誌更新，與 UART／手機網頁連線分開呈現。
- **最近紀錄**：首末告警接收時間、區間長度與最後告警時的 Wi-Fi 狀態，同類告警間隔不超過 2 秒合併，保留最近 100 段；可下載 JSON。

新版韌體每秒輸出 `[NIDS_LINK] connected=1/0`，網頁即使在 ESP32 開機後才啟動，也能在約 1–2 秒內確認連線狀態；這是板端實際連線旗標，不依流量猜測。請先停止 collector、燒錄新版，再重開網頁：

```powershell
idf.py -p COM3 flash
.\scripts\start_demo_dashboard.ps1
```

若仍使用沒有此回報的舊韌體，第一次可能顯示「尚未確認」；啟動 collector 後按 EN/RESET，讓它捕捉完整連線日誌。新版通常不需要這個步驟。資料過期時仍保留最後觀測值並提示過期，不將網頁連線正常當成 ESP32 已連線。

五秒未收到新 UART 行會標成資料過期；超過兩秒無新偵測視窗時，先顯示等待偵測資料。正告警後若兩秒沒有新正告警，頁面停止顯示持續告警。這些是展示的新鮮度規則，不會修改板端模型或 CSV 標籤。

## 展示順序

1. 正常：手機顯示「監控中」，Wi-Fi「已連線」，UART「持續接收」。
2. 攻擊：首頁大字變為「偵測到異常」，顯示類型並增加紀錄。
3. 若真的斷線：Wi-Fi 顯示「已斷線」，UART 仍可持續更新。
4. 停止攻擊：觀察新警報停止、連線恢復與歷史紀錄保留。此系統是 IDS，網頁不宣稱已攔截或消滅攻擊。

若攻擊也中斷手機到電腦的 Wi-Fi，手機頁面將顯示網路中斷，恢復後自動更新。現場主展示可使用電腦瀏覽器；需要手機全程不中斷時，讓手機與電腦使用另一條獨立的展示網路，ESP32 透過 USB 連到電腦即可。

攻擊名稱來自板端 `attack=1`、`m3src` 與對應訊框計數；`pred` 原始樹票和 START/STOP 標籤不會單獨產生網頁警報。無線來源內採用與 OLED 相同的名稱優先序，名稱是推定類型，並非新增多類別分類器。ARP 代表 gateway-MAC 身分變更，Deauth／Disassoc 不拆成兩種。

## 測試

```powershell
python -m unittest scripts.test_demo_dashboard -v
```

測試涵蓋斷線／重連／恢復、初次連線、資料缺口、USB 中斷、開機重置、告警來源、HTTP 與本機字型資源，不需接板；真實攻擊與手機連線須依上方順序驗證。原始 CSV／日誌長期保留，網頁歷史為記憶體內的本次啟動紀錄；新版 Ctrl+C 時會自動保存 `<CSV檔名>.dashboard.json`。重開程式後畫面重新計算，舊場次仍可從自動摘要或 `.csv.log` 重建，不必依賴手動下載。

## 告警列表的短暫事件過濾

網頁預設不列出已結束、首末告警區間不足 1 秒的無線警報；正在發生的警報仍即時呈現。ARP 身分異常屬於事件訊號，保留並顯示「事件告警」，不把單次事件寫成 0 秒。畫面的近期告警數量依目前顯示的列表計算，最多來自最近 100 段原始紀錄。

此規則只整理展示畫面，不改板端判定，也不刪除 API、CSV、主控台日誌與下載 JSON 裡的原始紀錄。原始 0 秒是首末回報時間相同，不代表攻擊持續時間確定為零。顯示門檻在 `scripts/demo_web/assets/dashboard.js` 的 `MIN_COMPLETED_WIRELESS_SECONDS`，目前為 1 秒。
