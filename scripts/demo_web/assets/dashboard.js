const $ = id => document.getElementById(id);
let lastData = null, busy = false;
// Presentation filter only. CSV, API and downloaded records retain all events.
const MIN_COMPLETED_WIRELESS_SECONDS = 1;
function visibleAlerts(events) {
  return events.filter(e => e.active || e.type === 'ARP 身分異常' ||
    e.duration >= MIN_COMPLETED_WIRELESS_SECONDS);
}
function text(id, value) { const node = $(id); if (node.textContent !== String(value)) node.textContent = value; }
function duration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const n = Math.max(0, Math.floor(seconds)), h = Math.floor(n / 3600), m = Math.floor(n / 60) % 60, s = n % 60;
  return (h ? String(h) + ':' : '') + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
}
function clock(stamp) { return stamp ? stamp.split('T').pop() : '尚未恢復'; }
function node(tag, cls, value) { const e = document.createElement(tag); e.className = cls; if (value !== undefined) e.textContent = value; return e; }
function badge(label, cls = '') { return node('span', 'status-chip caption-3 ' + cls, label); }
function empty(title, description) { const e = node('div', 'empty body-6'); e.append(node('strong', 'title-4', title), document.createTextNode(description)); return e; }
function entries(id, items, kind) {
  const list = document.createDocumentFragment();
  if (!items.length) list.append(empty(kind === 'alert' ? '尚無告警' : '目前沒有斷線紀錄', kind === 'alert' ? '新的設備告警會顯示在這裡。' : '發生斷線後，將記錄重連過程與持續時間。'));
  function entry(e) {
    const row = node('article', 'entry');
    if (kind === 'alert') {
      row.append(node('h4', 'title-3', e.type), badge(e.active ? '持續告警' : '已記錄', e.active ? 'bad' : ''));
      const meta = node('div', 'meta caption-2');
      const singleEvent = e.type === 'ARP 身分異常';
      const interval = singleEvent && e.duration === 0 ? clock(e.start) : clock(e.start) + ' → ' + clock(e.last);
      const length = singleEvent ? '事件告警' : e.duration < 0.1 ? '剛偵測到' : e.duration.toFixed(1) + ' 秒';
      meta.append(node('span', '', interval), node('span', '', length));
      row.append(meta);
    } else {
      const done = e.outcome === 'recovered', interrupted = e.outcome === 'interrupted';
      row.append(node('h4', 'title-3', done ? '設備連線已恢復' : interrupted ? '紀錄中斷' : '設備連線中斷'), badge(done ? '已恢復' : interrupted ? '未確認恢復' : '尚未恢復', done ? 'good' : interrupted ? '' : 'warning'));
      const meta = node('div', 'meta caption-2');
      meta.append(node('span', '', clock(e.start) + ' → ' + (done ? clock(e.end) : interrupted ? '紀錄中斷' : '等待恢復')), node('span', '', (e.start_known || interrupted ? '' : '≥ ') + duration(e.duration)));
      row.append(meta);
      row.append(node('p', 'entry-note caption-2', '重連嘗試 ' + e.attempts + ' 次'));
    }
    return row;
  }
  items.slice(0, 5).forEach(e => list.append(entry(e)));
  if (items.length > 5) { const details = document.createElement('details'); const summary = node('summary', 'caption-1', '查看較早的 ' + (items.length - 5) + ' 筆紀錄'); details.append(summary); items.slice(5).forEach(e => details.append(entry(e))); list.append(details); }
  const signature = JSON.stringify(items);
  if ($(id).dataset.signature !== signature) { const open = $(id).querySelector('details')?.open; $(id).replaceChildren(list); $(id).dataset.signature = signature; if (open && $(id).querySelector('details')) $(id).querySelector('details').open = true; }
}
function connection(d) {
  const c = d.connection || {phase:'unknown',outages:[],total:0};
  const phase = c.phase, record = c.outages[0];
  const labels = {unknown:'尚未確認',connecting:'連線中',up:'已連線',down:'已斷線',reconnecting:'重連中',recovered:'已恢復'};
  text('phaseLabel', labels[phase]);
  $('phaseLabel').className = 'status-chip caption-3 ' + (['up','recovered'].includes(phase) ? 'good' : phase === 'down' ? 'bad' : ['connecting','reconnecting'].includes(phase) ? 'warning' : '');
  text('wifi', labels[phase]);
  text('wifiHint', phase === 'unknown' ? '等待最新連線回報' : d.ip ? d.ip : 'ESP32 無線連線');
  text('durationLabel', record?.outcome === 'recovered' ? '上次斷線時間' : '斷線持續時間');
  text('duration', phase === 'unknown' ? '—' : (record && !record.start_known && record.duration !== null ? '≥ ' : '') + duration(record?.duration));
  let detail = '目前連線穩定';
  if (phase === 'unknown') detail = '等待設備連線回報';
  else if (phase === 'connecting') detail = '設備正在建立連線';
  else if (phase === 'down') detail = '連線已中斷，等待重新連線';
  else if (phase === 'reconnecting') detail = '正在嘗試第 ' + record.attempts + ' 次重連';
  else if (phase === 'recovered') detail = '已重新取得 IP，設備連線恢復';
  else if (record?.outcome === 'recovered') detail = clock(record.end) + ' 恢復連線';
  text('recoveryDetail', detail);
  const step = phase === 'down' ? 0 : phase === 'reconnecting' ? 1 : (['up','recovered'].includes(phase) && record?.outcome === 'recovered') ? 2 : -1;
  [...$('steps').children].forEach((e,i) => e.className = i < step || i === step && step === 2 ? 'done' : i === step ? 'current' : '');
  entries('outages', c.outages, 'outage'); text('outageCount', c.total + ' 次');
  return phase;
}
function protection(p) {
  p = p || {fresh:false,mode:'unknown',action:'unknown',communication:'unknown',actions:[]};
  text('guardMode', !p.fresh ? '等待更新' : p.mode === 'on' ? '防護開啟' : p.mode === 'off' ? '防護關閉' : '尚未確認');
  const actions = {locked:'已修復並鎖定',watch:'監看中',detected:'發現閘道器異常',error:'修復失敗',invalid:'尚未設定可信任網路',waiting:'等待指定網路',unknown:'尚未確認'};
  text('guardAction', p.fresh ? actions[p.action] || '尚未確認' : '等待防護回報');
  text('guardDetail', !p.fresh ? '請確認設備持續傳送資料' : p.mode === 'off' ? '僅偵測，不修改 ARP 映射' : p.action === 'locked' ? '已完成 ' + p.repairs + ' 次修復' : '比對事先設定的可信任閘道器');
  const comm = {unknown:'尚未驗證',checking:'驗證中',reachable:'可正常通訊',recovered:'通訊已恢復',failed:'未收到回覆',error:'驗證未完成'};
  text('probeStatus', comm[p.communication] || '尚未驗證');
  $('probeStatus').className = 'heading-5 ' + (['reachable','recovered'].includes(p.communication) ? 'probe-good' : p.communication === 'failed' ? 'probe-bad' : '');
  text('probeDetail', p.target ? p.target + ' · 已回覆 ' + p.received + ' / ' + p.sent + ' 次' : '等待實際測試回覆');
  const list = document.createDocumentFragment();
  for (const e of (p.actions || []).slice(0,3)) { const row = document.createElement('div');row.append(node('span','',clock(e.time)),node('span','', (e.mode === 'off' ? '防護關閉 · ' : '') + (actions[e.action] || '狀態更新')));list.append(row); }
  $('guardHistory').replaceChildren(list);
}

function render(d) {
  lastData = d;
  $('attackLine').hidden = d.state === 'alert';
  const phase = connection(d);
  protection(d.protection);
  let title = '監控中', desc = '持續觀察無線流量與設備狀態。', tone = 'monitoring';
  if (d.state === 'offline') { title = 'USB 連線中斷'; desc = '請檢查設備的 USB 連線。'; tone = 'warning'; }
  else if (d.state === 'stale') { title = '資料暫停更新'; desc = '請檢查設備電源與 USB 連線。'; tone = 'warning'; }
  else if (d.state === 'alert') { title = '偵測到異常'; desc = d.types.join(' · '); tone = 'alert'; }
  else if (phase === 'down') { title = '設備已斷線'; desc = '正在等待設備開始重連。'; tone = 'warning'; }
  else if (phase === 'reconnecting' || phase === 'connecting') { title = '正在重新連線'; desc = '連線恢復後，會保留這次中斷的紀錄。'; tone = 'warning'; }
  else if (phase === 'recovered') { title = '設備已恢復'; desc = '無線連線已恢復，持續觀察新告警。'; }
  else if (d.state === 'waiting') { title = '等待偵測資料'; desc = '設備尚未傳來新的偵測結果。'; tone = 'warning'; }
  text('status', title); text('description', desc); $('statusMark').className = 'status-mark ' + tone;
  const fresh = d.serial && d.age !== null && d.age < 5;
  $('live').className = 'live caption-1' + (fresh ? ' ok' : ''); text('liveText', fresh ? '即時連線' : '等待資料');
  text('attack', d.types.length ? d.types.join(' · ') : d.state === 'monitoring' ? '無新告警' : '等待更新');
  text('uart', !d.serial ? '已中斷' : fresh ? '持續接收' : d.age === null ? '等待資料' : '暫停更新');
  text('uartHint', d.age === null ? 'USB 連接電腦' : d.age < 1 ? '剛剛收到資料' : Math.floor(d.age) + ' 秒前收到資料');
  const shownAlerts = visibleAlerts(d.events);
  text('count', shownAlerts.length); text('alertCount', shownAlerts.length + ' 段');
  text('lastAlert', shownAlerts.length ? '最近 ' + clock(shownAlerts[0].last) : '尚無符合條件的告警');
  entries('events', shownAlerts, 'alert');
  text('session', '本次啟動於 ' + clock(d.started)); text('updated', '更新於 ' + new Date().toLocaleTimeString('zh-TW', {hour12:false}));
  $('error').hidden = !d.error; text('error', d.error ? 'UART 讀取失敗：' + d.error : ''); $('download').disabled = false;
}
function networkLost() {
  protection(null);
  text('status', '網頁連線中斷'); text('description', '請確認手機與電腦在同一網路，恢復後會自動更新。');
  $('statusMark').className = 'status-mark warning'; text('liveText', '等待網路'); $('live').className = 'live caption-1';
  text('attack', '等待更新'); text('wifi', '目前無法確認'); text('wifiHint', '等待網頁重新連線');
  text('uart', '目前無法確認'); text('uartHint', '等待網頁重新連線'); text('phaseLabel', '等待更新'); $('phaseLabel').className = 'status-chip caption-3';
  text('duration', '—'); text('recoveryDetail', '等待最新設備狀態'); [...$('steps').children].forEach(e => e.className = '');
  for (const chip of document.querySelectorAll('.entry .status-chip.bad,.entry .status-chip.warning')) { chip.textContent = '最後紀錄'; chip.className = 'status-chip caption-3'; }
  $('events').dataset.signature = ''; $('outages').dataset.signature = '';
}
async function update() {
  if (busy) return; busy = true;
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 4000);
  try { const response = await fetch('/api/status', {cache:'no-store', signal:controller.signal}); if (!response.ok) throw Error(response.status); render(await response.json()); }
  catch (_) { networkLost(); } finally { clearTimeout(timeout); busy = false; }
}
$('download').onclick = () => {
  if (!lastData) return;
  try { const blob = new Blob([JSON.stringify(lastData,null,2)],{type:'application/json'}), url = URL.createObjectURL(blob), a = document.createElement('a');
    a.href = url; a.download = 'esp32-records-' + new Date().toISOString().replace(/[:.]/g,'') + '.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
  } catch (_) { $('error').hidden = false; text('error', '紀錄匯出失敗，請稍後重試。'); }
};
update(); setInterval(update,500);
