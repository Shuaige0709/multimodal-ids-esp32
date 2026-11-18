# 燕子守望動態效果

已把 [shader-effects-inc/shaders](https://github.com/shader-effects-inc/shaders) 接入既有純 JavaScript 網頁。使用 MIT 開源套件 `shaders@4.0.7`，不需要 React、不需帳號或 Pro 訂閱。

## 看效果

停止舊網頁服務，再使用已有的日誌：

```powershell
.\scripts\start_demo_replay.ps1 -Scene Recovery
```

開啟 `http://localhost:8080`，把滑鼠移到燕子圖或輕觸。主畫面文字仍完整保留，動態效果集中在獨立插圖，不蓋住告警／通訊狀態。回放結束、資料暫停或頁面離開前景時，動態會停止，避免讓畫面看起來仍在即時接收資料。

## 選用的兩個效果

- **Ripples**：燕子周圍向外擴散的波紋。
- **CursorRipples**：滑鼠與觸控帶來的波紋擾動，疊在 Ripples 外層。

配色沿用目前顯示狀態：綠色為監看、紅色為告警、琥珀色為連線／資料異常。這是裝飾性視覺，不是 RF 強度圖、封包數量或模型信心值，也不參與偵測或防護。

動態融入主區底色，沒有獨立框線、白底徽章或互動提示；「動態效果／Motion」按鈕收在技術資訊內，可暫停並記住偏好；系統設定減少動態效果時優先遵守，顯示靜態圖。沒有加入閃爍或整頁扭曲。

## 電腦與手機的差異

套件的原生效果使用 WebGPU。電腦 `localhost` 且瀏覽器／GPU 支援時載入兩個真正的 shader；手機透過 `http://電腦IP:8080` 通常不是安全環境，會自動改用本機 Canvas 2D 的簡化波紋與觸控漣漪。GPU 不可用或啟動失敗也會使用這個相容版本。

相容版上限 30 fps、DPR 上限 1.5，指標互動最多保留 8 個波紋；不需要為展示額外架設 HTTPS。兩種呈現均不會更改模型、UART 或資料。原生與相容版的波紋外觀略有差異。

## 安裝與維護

依賴已在 `scripts/demo_web/effects/` 本機安裝，版本記錄於 `package-lock.json`。已產生離線 bundle，正常啟動 Python 網頁不需要另外執行 npm，也沒有 CDN 或字型外連。原生引擎約 1.3 MB，僅在支援 WebGPU 的情況下動態載入。

若未來調整原生效果參數，修改 `effects/shader-engine.mjs` 再重建：

```powershell
cd scripts\demo_web\effects
npm ci --ignore-scripts
npm run build
```

瀏覽器啟動與相容版位於 `assets/watch-effects.js`；只改這份不需要 npm build。Python 服務啟動時會讀取靜態資源，因此修改後要重新啟動網頁服務。

build 使用套件公開的自訂 components 入口，只供應 Ripples 與 CursorRipples；以本機建置 alias 排除預設全元件 registry，避免整套特效一併進入 bundle。沒有修改 node_modules 原始碼。內建 telemetry 明確設為 `disableTelemetry: true`，不使用線上 preview API。

授權通知存於 `assets/shaders-LICENSE.txt`，包含 shaders 與相關執行時依賴。node_modules 已排除 Git，應保留 package／lock、建置原始碼與已產生的 assets。

## 已驗證

- Chrome 原生 WebGPU adapter 實際呈現兩層 shader，沒有 shader 編譯或頁面錯誤。
- 區網 HTTP 條件的 Canvas 相容版、手機 390 px、原有中英文與 320–1280 px 版面檢查。
- 互動、配色、動態開關、減少動態效果，以及測試中沒有任何外部網路請求。
- 原本的資料與恢復狀態測試維持通過；沒有新增實驗錄製。

參考：[官方 JavaScript 用法](https://github.com/shader-effects-inc/shaders#javascript)、[Ripples API](https://shaders.com/docs/components/ripples)。
