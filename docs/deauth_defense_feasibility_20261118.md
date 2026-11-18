# PMF 以外的 Deauth 防禦：現有 ESP32 是否適用？

查核日期：2026-11-18。範圍是現有 ESP32 station、ESP-IDF 5.5.3 公開 API、單射頻與目前一般 AP；沒有新增攻擊實驗或更動韌體。

## 結論與決策

**有 PMF 以外的真實防禦研究，不能說世界上只有 PMF。** 但查到的有效替代方案，主要需要修改接收端 Wi-Fi 韌體／MAC 處理，或採用可程式化 AP。它們不是在現有 IDS 的應用層多加一條規則，就能阻止 ESP32 被踢下線。

對「保留現有硬體、一般 AP 與 ESP-IDF 公開 API，短時間新增真正不中斷的 Deauth 防禦」這個條件，**本次沒有找到經驗證、可直接移植的方案**。建議維持目前的偵測、退避重連與通訊恢復展示。這是根據介面能力與研究實作條件的高信心工程判斷，不是數學上證明不存在任何私有韌體方法。

## 已核實的替代方案

### 1. 延後執行 Deauth，再用後續資料確認

Bellardo 與 Savage，**802.11 Denial-of-Service Attacks: Real Vulnerabilities and Practical Solutions**，USENIX Security 2003。

- 原文提出延後執行斷線要求，若之後仍收到該端點資料，就取消可疑斷線要求；以修改過的 AP 與 10 秒延遲進行實驗。
- 這是 PMF 前的非密碼學防禦，而且確實有實作。代價包括漫遊時狀態保留與轉送問題。
- **我們的限制：** 必須能介入收到斷線訊框後的 MAC 狀態轉換。對送往 station 的偽造訊框，僅修改 AP 不能自動讓 ESP32 station 忽略它；station 接收端也需要相應能力。

[USENIX 原文，Deauthentication 一節](https://www.usenix.org/legacy/events/sec03/tech/full_papers/bellardo/bellardo_html/)

### 2. RF 身分辨識＋AP 端狀態機，在斷線前丟棄偽造訊框

Zanna、Radcliffe 與 Kumar，**Preventing Attacks on Wireless Networks Using SDN Controlled OODA Loops and Cyber Kill Chains**，Sensors 2022，22(23)，9481，DOI `10.3390/s22239481`。

- 使用 RF 身分特徵、每端點狀態機與 P4 控制的動作，包括丟棄不可信管理訊框。
- 實作使用客製 Openwifi FPGA 與驅動；無須修改一般 client 的前提，是防護能力已放在其 AP 系統內。
- **我們的限制：** 目前 ESP32 是受監控 station，不是該可程式化 AP。只保留 RSSI、在 callback 裡忽略一筆資料，並不等於把 Wi-Fi MAC 將要處理的斷線訊框攔下。

[論文全文及 Section 2、Appendix A](https://doi.org/10.3390/s22239481)

### 3. 修補標準與 Wi-Fi 實作中的斷線弱點

Schepers、Ranganathan 與 Vanhoef，**On the Robustness of Wi-Fi Deauthentication Countermeasures**，ACM WiSec 2022，DOI `10.1145/3507657.3528548`。

- 研究指出，即使使用管理訊框保護，特定標準與實作缺陷仍可能導致斷線；作者提供 PoC 與修補資訊。
- **適用判斷：** 更新 AP／client 韌體是有意義的維護，但不能把針對特定弱點的修補，當成非 PMF 網路已能辨識所有偽造 Deauth 的證據；也不能承諾 PMF 能防全部 DoS。

[作者公開全文](https://papers.mathyvanhoef.com/wisec2022.pdf)；[作者程式與修補資料](https://github.com/domienschepers/wifi-deauthentication)

## ESP32 的關鍵介面邊界

已核對官方 v5.5.3 文件與本機 `esp_wifi.h`：

- `wifi_promiscuous_cb_t` 回傳型別為 `void`，是接收觀測通知，沒有公開的 accept/drop 回傳值。
- `esp_wifi_set_promiscuous_filter()` 篩選的是送給 promiscuous 接收路徑的訊框；文件未提供藉此禁止 station MAC 執行 Deauth 的能力。
- 應用層收到 `WIFI_EVENT_STA_DISCONNECTED` 時，驅動已回報連線中斷；文件也描述網路介面及 socket 的後續清理。忽略這個通知不能讓已失去的無線連線保持正常。

因此，**「看到並辨識攻擊」與「在 MAC 執行斷線前攔截攻擊」是不同權限。** 上述公開介面支持前者；本次未找到後者的可用公開 hook。這是我們不直接移植上述防禦的主要原因，不是 RAM 或決策樹準確率不足。

[官方 Wi-Fi API：callback 型別與 promiscuous filter](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/api-reference/network/esp_wifi.html)；[官方 driver guide：disconnect 與 sniffer](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/api-guides/wifi.html)

## 不應誤認為阻擋成功的做法

- **MAC 黑名單：** 偽造訊框可以使用真實 AP 的來源 MAC；禁止該 MAC 可能連可信任 AP 都排除，且 promiscuous 層黑名單不等於 MAC 層阻擋。
- **BSSID 綁定：** 可限制重新連線對象，有助避免連錯 AP，但不驗證每個 Deauth 的真偽。
- **加快重連、保留資料、UART 備援：** 分別改善恢復與展示可觀測性，不能聲稱 Wi-Fi 在攻擊中未中斷。
- **自行換 station 頻道：** 原 AP 沒跟著換就無法維持該連線；協同 AP 搬遷是另一項基礎設施設計，也不保證攻擊者不跟隨。
- **任意修改 Wi-Fi 私有 binary：** 不排除研究可能性，但沒有足夠證據支持在這次競賽前作為可靠工程交付，故不納入。

## 競賽建議說法

> Our system detects deauthentication activity and automatically reconnects after disruption. Preventing forged disconnects requires management-frame protection or control of the Wi-Fi MAC/AP processing path, which is outside our current application-level ESP32 interface.

本次現場證據可支持約 22.2 秒的一段失聯後恢復，以及 ARP 攻擊期間保持閘道器可達；不需要為本項研究結論再增加錄製。
