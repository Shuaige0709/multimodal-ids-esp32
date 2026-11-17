# ARP 自動修復／鎖定：可複製測試手冊

目標：比較同一 ESP32、同一 AP、同一種 ARP 欺騙，在防護關閉與開啟時，閘道器回覆是否中斷、是否恢復。這不是 Wi-Fi 斷線測試；ARP 攻擊時 Wi-Fi 可能一直保持已連線。

## 0. 已填好的設定與設備

這次從 Windows 的閘道器鄰居表及最近 ESP32 UART 紀錄交叉確認：

- Gateway：`192.168.0.1`，可信任 MAC `68:02:B8:BB:EC:D4`。
- ESP32 的 AP BSSID：`68:02:B8:BB:AF:57`。
- 電腦 Wi-Fi AP BSSID 結尾 `56`，**不能拿它取代 ESP32 的 `57`**。
- ESP32 的 IP 每場由新韌體回報，下面的工具會直接印出 Kali 指令，不必自己猜。
- Windows + ESP32 USB/UART + Kali；不需要 Pi。USB 線全程接電腦。

本機信任設定在 `main/arp_guard_profile.h`，已先準備為 **Off**，不從攻擊期間的 ARP 回覆學習信任。若 AP／閘道器換過，先在無攻擊時核對路由器管理頁，再修改設定；不符合指定 AP 與閘道器時會顯示「等待指定網路」，不自動鎖定。

第一次建立／重新填入本次設定，使用 Windows 專題終端：

```powershell
cd C:\Users\yanwe\OneDrive\Desktop\Projects\espidf\nids_esp32_project
.\scripts\configure_arp_guard.ps1 -Mode Off -GatewayIP 192.168.0.1 -GatewayMac 68:02:B8:BB:EC:D4 -Bssid 68:02:B8:BB:AF:57
```

## 1. 先錄防護關閉 OFF_01

先在舊 collector 視窗按 Ctrl+C，若 ESP-IDF monitor 開著則按 Ctrl+]。接著在 **ESP-IDF PowerShell** 貼上：

```powershell
cd C:\Users\yanwe\OneDrive\Desktop\Projects\espidf\nids_esp32_project
.\scripts\configure_arp_guard.ps1 -Mode Off
idf.py build
idf.py -p COM3 flash
.\scripts\start_demo_dashboard.ps1 -RunName ARP_OFF_01
```

每個命令成功後才執行下一個。若 `idf.py` 不存在，先執行 `. C:\esp\v5.5.3\esp-idf\export.ps1`。

網頁開 `http://localhost:8080`；手機使用終端列出的 Phone 網址。

**先不要攻擊，等 30 秒：**

- 設備連線：已連線。
- ARP 自動防護：防護關閉／監看中。
- 通訊驗證：目標 `192.168.0.1`，連續收到三次實際 ICMP 回覆後顯示「可正常通訊」。

如果這時已經顯示「未收到回覆」，先停止對照測試。先確認路由器是否允許 ICMP、設定是否符合，以及網路中是否還有其他 ARP 工具。正常基線不通時，後面不能宣稱防護恢復通訊。

另開一個 **一般 Windows PowerShell**，印出本場可直接貼到 Kali 的指令：

```powershell
cd C:\Users\yanwe\OneDrive\Desktop\Projects\espidf\nids_esp32_project
.\scripts\print_arp_guard_targets.ps1
```

工具會輸出一組 `export ...`／`sudo ...` 指令，並盡量自動填入 Windows VMnet1 標籤位址。等下面 Kali 準備好後，直接複製這一組指令；它使用網頁目前收到的 ESP32 IP。

## 2. Kali：同一個單向 ARP 測試，60 秒

在 **Kali 原本的專題目錄終端**，先準備 managed Wi-Fi：

```bash
cd "$(git rev-parse --show-toplevel)"
chmod +x ./host/attacks/arp_guard_test.sh
sudo -v
sudo ./host/attacks/prepare_wifi.sh managed
nmcli device wifi connect '302' ifname wlan0 --ask
```

若已連到 `302`，不必重做連線；`--ask` 只會在需要時詢問 Wi-Fi 密碼。網卡不是 wlan0 時，沿用先前已設定的 `NIDS_WIFI_IFACE`，並在 nmcli 指令替換成相同網卡。

現在貼上剛才 Windows 工具印出的一組指令，它已填好本場 ESP32 IP、Gateway IP、60 秒時長與腳本名稱，不需要手動修改。看到 `One-way fixture` 後確認目標是自己的 ESP32，再觀察網頁。

腳本只對 ESP32 宣告假的 Gateway MAC，不毒化路由器的回程表，並暫時關閉 Kali 的 IP forwarding，讓被導到 Kali 的封包無法代轉。正常結束或 Ctrl+C 時，會停止攻擊、送 STOP 標籤、恢復原本 forwarding 設定。請勿在同一台 Kali 同時執行其他依賴 forwarding 的實驗。若強制關閉 VM／kill -9，清理可能無法執行；重新測試前檢查 `sysctl net.ipv4.ip_forward`。

**OFF 預期觀察：**ARP 異常告警、防護仍關閉、實際 Ping 回覆可能中斷。若整場仍通訊正常，先查可見性、ARP 工具是否持續存活、AP client isolation；不能把沒有影響的 OFF 場當成防護有效的證據。

攻擊結束後保持 collector 再錄 **30 秒**，觀察自然恢復。接著在 Windows 一般 PowerShell 匯出本場網頁紀錄：

```powershell
$stamp = Get-Date -Format yyyyMMdd_HHmmss
Invoke-RestMethod http://localhost:8080/api/status | ConvertTo-Json -Depth 12 | Set-Content "data\raw\ARP_OFF_01_$stamp.json" -Encoding utf8
```

回 collector 終端按 Ctrl+C。CSV 和完整 `.csv.log` 已自動儲存，檔名包含 `ARP_OFF_01`，不用填 QC 或 manifest。

## 3. 再錄防護開啟 ON_01

先確認 Kali 攻擊已停止，Windows collector 已 Ctrl+C。ESP-IDF PowerShell 貼上：

```powershell
.\scripts\configure_arp_guard.ps1 -Mode On
idf.py build
idf.py -p COM3 flash
.\scripts\start_demo_dashboard.ps1 -RunName ARP_ON_01
```

Flash 會重新開機，清除上一場 RAM 中的 ARP 表與鎖定狀態。ON 開始時應是「防護開啟／監看中」，不應因上一場已鎖定而跳過新的觸發過程。

正常等 30 秒並確認「可正常通訊」，另開 Windows 終端重新取得本場指令：

```powershell
.\scripts\print_arp_guard_targets.ps1
```

在 Kali 同一個專題終端貼上新輸出的一組指令，執行完全相同的 60 秒腳本。

**ON 預期順序：**

1. 觀測到 Gateway MAC 不符可信任設定，產生 ARP 身分異常事件。
2. ESP32 在 lwIP TCP/IP 執行緒中寫回正確映射並加上靜態鎖定；API 成功且讀回值符合才顯示「已修復並鎖定」。
3. 真正收到三次連續 Ping 回覆，才顯示可通訊。
4. 先前有兩次連續 timeout、修復後再有三次連續回覆，才顯示「通訊已恢復」。如果防護夠快、從未觀測到持續中斷，會顯示「可正常通訊」，不用為了畫面漂亮故意延遲防護。

攻擊停止後再錄 30 秒，匯出：

```powershell
$stamp = Get-Date -Format yyyyMMdd_HHmmss
Invoke-RestMethod http://localhost:8080/api/status | ConvertTo-Json -Depth 12 | Set-Content "data\raw\ARP_ON_01_$stamp.json" -Encoding utf8
```

按 Ctrl+C 結束 collector。若第一組正常，建議再依同樣順序各重複一場，僅將 `-RunName` 改成 `ARP_OFF_02`、`ARP_ON_02`，保留相同攻擊時長及場地。

## 4. 比較哪些結果

- **映射保護**：OFF 的 mismatch 是否持續；ON 是否成功鎖定，`err=0`。
- **通訊**：攻擊期間的 Ping 成功／timeout，不能只比較整場含正常區間的總成功率。
- **修復後**：攻擊仍在持續時是否已恢復回覆；如果只有 STOP 之後才恢復，不能算自動防護成功。
- **不中斷 Wi-Fi**：是否仍保持連線，而非透過主動斷線避開觀測。
- **誠實標示**：網頁驗證的是「到閘道器的 ICMP 回覆」，不等於所有 Internet 服務、TLS 安全或完整防中間人。首批真實場次尚待你錄製後分析。

可直接搜尋原始日誌中的 `[ARP_GUARD_EVENT]`、`[ARP_GUARD]`、`[ARP_PROBE]`；完整 `.csv.log` 是防護與通訊證據。CSV 延續既有欄位，防護／Probe 記錄不塞進原模型輸入；JSON 方便審閱當次摘要與最近動作。

## 5. 延伸：原本雙向 ARP 攻擊

完成單向對照後，才測原本的雙向腳本：

```bash
export NIDS_ARP_DURATION='60'
sudo -E ./host/attacks/arpspoof.sh
```

它同時毒化 ESP32 與路由器，而且開啟 forwarding。ESP32 鎖定自己的表，無法修復路由器那一側；因此可能出現「已鎖定，但仍未收到回覆」，或封包仍能透過攻擊者轉送。請把這類結果作為防護範圍分析，不與單向 blackhole 場混算。

## 6. 關閉／恢復原本使用方式

```powershell
.\scripts\configure_arp_guard.ps1 -Mode Off
idf.py build
idf.py -p COM3 flash
.\scripts\start_demo_dashboard.ps1
```

開關都不需要修改 Kali function name。鎖定只在 RAM，關閉後重燒／重啟就不會沿用該靜態項目。換 AP 時需重新確認可信任設定；新版不會把陌生網路自動學成可信任。

實作依據：[ESP-IDF ICMP Echo](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/api-reference/protocols/icmp_echo.html)、[lwIP 靜態 ARP](https://github.com/lwip-tcpip/lwip/blob/master/src/core/ipv4/etharp.c)。
