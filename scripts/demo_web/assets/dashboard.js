const $ = id => document.getElementById(id);
let language = 'zh', lastData = null, busy = false, fetchFailed = false;
try { if (localStorage.getItem('swallow-language') === 'en') language = 'en'; } catch (_) {}
const requestedLanguage=new URLSearchParams(location.search).get('lang');
if(['zh','en'].includes(requestedLanguage))language=requestedLanguage;
const COPY = {
  effectsArt:['互動燕子圖','Interactive swallow illustration'],effectsToggle:['動態效果','Motion'],
  brand:['燕子守望','Swallow Watch'],skip:['跳至監控內容','Skip to monitoring'],overview:['即時監控','Monitoring overview'],
  deviceWatch:['ESP32 無線安全監控','ESP32 wireless security'],currentAlert:['目前告警','Current alert'],
  connectionPanel:['裝置連線與恢復','Device connection and recovery'],connectionTitle:['裝置通訊','Device connectivity'],
  outageTime:['本次中斷時間','Current outage'],routerResponse:['路由器回應','Router response'],
  protectionTitle:['自動防護','Automatic protection'],verification:['通訊確認','Connectivity check'],
  history:['最近發生的事','Recent activity'],export:['匯出紀錄','Export records'],alerts:['攻擊告警','Attack alerts'],outages:['斷線與恢復','Connection history'],
  technical:['技術資訊','Technical details'],usbData:['USB 資料','USB data'],deviceIp:['裝置 IP','Device IP'],
  apPolicy:['AP 連線限制','AP connection policy'],probeCounts:['路由器測試回覆','Router test replies'],repairAttempts:['修復通知次數','Repair announcements'],
  pmfPolicy:['PMF 設定','PMF policy'],footer:['燕子守望 · ESP32 入侵偵測','Swallow Watch · ESP32 intrusion detection'],
  waiting:['等待資料','Waiting for data'],unconfirmed:['尚未確認','Not confirmed'],connected:['已連線','Connected'],disconnected:['已斷線','Disconnected'],
  reconnecting:['重連中','Reconnecting'],connecting:['連線中','Connecting'],restored:['已恢復','Restored'],
  linkWaiting:['等待連線回報','Waiting for device status'],linkUp:['Wi-Fi 已連線','Wi-Fi connected'],linkDown:['Wi-Fi 已斷線','Wi-Fi disconnected'],
  linkRetry:['正在重新連線','Reconnecting to Wi-Fi'],linkConnecting:['正在連接 Wi-Fi','Connecting to Wi-Fi'],
  linkUnknown:['尚未收到最新連線狀態。','Waiting for a recent connection update.'],linkStable:['裝置與無線基地台保持連線。','The device is connected to its access point.'],
  linkLost:['裝置已失去無線連線，正在等待重連。','The wireless connection is down. Waiting to reconnect.'],
  retryDetail:['已嘗試 {n} 次，持續等待連線恢復。','{n} connection attempts. Waiting for the link to return.'],
  linkingDetail:['正在建立裝置的無線連線。','Establishing the wireless connection.'],
  commAffected:['通訊仍受影響','Communication affected'],commAffectedDetail:['Wi-Fi 仍連線，但路由器沒有回覆測試。','Wi-Fi is connected, but the router is not answering checks.'],
  routerWait:['等待 Wi-Fi 恢復','Waiting for Wi-Fi'],routerUnknown:['等待確認','Awaiting confirmation'],routerChecking:['確認中','Checking'],
  routerOk:['回應正常','Responding'],routerRecovered:['已恢復回應','Responding again'],routerFailed:['沒有回應','Not responding'],routerError:['測試未完成','Check incomplete'],
  lastRecovery:['上次中斷 {duration}，現已恢復','Previous outage: {duration}, now restored'],recoveryAt:['{time} 恢復 Wi-Fi 連線','Wi-Fi restored at {time}'],
  noAlert:['目前無告警','No current alerts'],watching:['持續監看中','Monitoring'],watchingDetail:['持續觀察無線流量與裝置狀態。','Watching wireless traffic and device status.'],
  attackDetected:['發現攻擊跡象','Attack activity detected'],usbLost:['USB 已中斷','USB disconnected'],usbLostDetail:['請檢查裝置的 USB 連線。','Check the device USB connection.'],
  stale:['資料暫停更新','Updates paused'],staleDetail:['目前無法確認裝置的最新狀態。','The latest device state cannot be confirmed.'],
  waitDevice:['等待設備資料','Waiting for the device'],waitDeviceDetail:['連接設備後，即可查看監控狀態。','Connect the device to view monitoring updates.'],
  active:['持續告警','Active'],logged:['已記錄','Recorded'],pointEvent:['單次事件','Single event'],justDetected:['剛偵測到','Just detected'],
  sec:['{n} 秒','{n} s'],count:['{n} 筆','{n} records'],more:['查看較早的 {n} 筆紀錄','Show {n} earlier records'],
  emptyAlert:['尚無告警紀錄','No alert records'],emptyAlertDetail:['符合顯示條件的告警會出現在這裡。','Alerts meeting the display criteria will appear here.'],
  emptyOutage:['尚無斷線紀錄','No outages recorded'],emptyOutageDetail:['連線中斷與恢復後，會留下時間紀錄。','Outage and recovery times will appear here.'],
  outageDone:['Wi-Fi 連線已恢復','Wi-Fi connection restored'],outageOpen:['Wi-Fi 連線中斷','Wi-Fi connection lost'],outageInterrupted:['連線紀錄中斷','Connection record interrupted'],
  notVerified:['未確認恢復','Recovery unconfirmed'],awaitRecovery:['等待恢復','Awaiting recovery'],recordStopped:['紀錄中斷','Record interrupted'],
  retryCount:['重連嘗試 {n} 次','{n} reconnect attempts'],
  guardOn:['防護開啟','Protection on'],guardOff:['防護關閉','Protection off'],guardWait:['等待防護回報','Waiting for protection status'],
  guardLocked:['已鎖定可信任路由器','Trusted router locked'],guardWatching:['正在檢查路由器身分','Checking router identity'],
  guardDetected:['發現路由器冒充跡象','Possible router impersonation'],guardError:['修復未完成','Repair incomplete'],guardInvalid:['尚未設定可信任路由器','Trusted router not configured'],
  guardNetwork:['等待指定的 Wi-Fi 網路','Waiting for the configured Wi-Fi'],guardGarp:['已送出修復通知','Repair announcement sent'],guardGarpError:['修復通知未送出','Repair announcement failed'],
  guardPartial:['防護已啟動，通訊仍受影響','Protection active, communication affected'],
  guardLockedDetail:['避免裝置將資料送往冒充的路由器。','Keeps the device from sending data to an impersonated router.'],
  guardCounts:['ARP 異常修復 {repairs} 次 · 重連後恢復防護 {rearms} 次','ARP anomaly repairs: {repairs} · Protection restored after reconnect: {rearms}'],
  guardRepair:['已修復 ARP 異常並鎖定路由器','ARP anomaly repaired; trusted router locked'],
  guardRearm:['重連後已恢復防護','Protection restored after reconnect'],
  guardOffDetail:['只偵測異常，不自動更正連線設定。','Detects anomalies without automatically correcting connection settings.'],
  guardWatchDetail:['比對事先確認的路由器身分。','Checks the router against the trusted configuration.'],guardNoData:['尚未收到最新防護狀態。','Waiting for a recent protection update.'],
  guardPartialDetail:['已保護本機設定；路由器端的回程仍可能受影響。','Local settings are protected; the return path may still be affected.'],
  commOk:['路由器回應正常','Router is responding'],commRecovered:['通訊已恢復','Communication restored'],commFailed:['路由器沒有回應','Router is not responding'],
  checkDetail:['確認裝置是否能與路由器往返通訊。','Checks whether the device can exchange traffic with its router.'],
  offPrefix:['防護關閉 · ','Protection off · '],usbReceiving:['持續接收','Receiving'],usbWaiting:['等待更新','Awaiting update'],
  bound:['限定可信任 AP','Trusted AP only'],unbound:['未限制 AP','AP not restricted'],pmfRequired:['Required（要求支援）','Required'],pmfOptional:['Optional（相容模式）','Optional'],
  live:['持續更新','Live updates'],recorded:['已錄製資料','Recorded data'],playback:['已錄製資料回放 · {file} · {time}','Recorded playback · {file} · {time}'],
  playbackEnd:['回放已結束','Playback finished'],playbackEndDetail:['以上為既有實驗紀錄，不是目前的現場狀態。','This is an existing experiment record, not the current live state.'],
  session:['本次開始於 {time}','Session started at {time}'],updated:['更新於 {time}','Updated at {time}'],
  webLost:['網頁連線中斷','Dashboard connection lost'],webLostDetail:['請確認手機與電腦的網路連線，恢復後會自動更新。','Check the phone and computer network connection. Updates resume automatically.'],
  lastRecord:['最後紀錄','Last recorded'],exportError:['紀錄匯出失敗，請稍後重試。','Could not export records. Please try again.'],
  deauth:['強制斷線攻擊','Deauthentication / Disassociation'],probe:['探測封包洪水','Probe flood'],beacon:['基地台廣播洪水','Beacon flood'],
  twin:['偽裝基地台','Evil twin'],arp:['路由器身分異常（ARP）','Router identity anomaly (ARP)'],wireless:['無線流量異常','Wireless traffic anomaly'],other:['未分類告警','Unclassified alert']
};
function tr(key, vars={}) { return (COPY[key]?.[language === 'en' ? 1 : 0] || key).replace(/\{(\w+)\}/g,(_,k)=>String(vars[k] ?? '')); }
function text(id,value) { const n=$(id); if(n.textContent!==String(value)) n.textContent=value; }
function node(tag,cls,value) { const e=document.createElement(tag);e.className=cls;if(value!==undefined)e.textContent=value;return e; }
function badge(label,cls='') { return node('span','status-chip caption-3 '+cls,label); }
function clock(stamp) { return stamp ? stamp.split('T').pop().replace(/\.\d+.*$/,'') : '—'; }
function duration(value) { if(value===null||value===undefined)return '—';const n=Math.floor(Math.max(0,value));return (n>=3600?Math.floor(n/3600)+':':'')+String(Math.floor(n/60)%60).padStart(2,'0')+':'+String(n%60).padStart(2,'0'); }
function seconds(n) { return n===null||n===undefined?'—':tr('sec',{n:Number(n).toFixed(1)}); }
const TYPE_KEYS={'Deauth / Disassoc':'deauth','Probe Flood':'probe','Beacon Flood':'beacon','Evil Twin':'twin','ARP 身分異常':'arp','無線異常':'wireless','未分類告警':'other'};
function attackName(type) { return TYPE_KEYS[type]?tr(TYPE_KEYS[type]):type; }
// Display filter only; raw API, exports and CSV retain all events.
function visibleAlerts(events) { return events.filter(e=>e.active||e.type==='ARP 身分異常'||e.duration>=1); }
function empty(title,description) { const e=node('div','empty body-6');e.append(node('strong','title-3',title),document.createTextNode(description));return e; }
function entries(id,items,kind) {
  const signature=JSON.stringify([language,items]);if($(id).dataset.signature===signature)return;
  const fragment=document.createDocumentFragment();
  if(!items.length)fragment.append(empty(tr(kind==='alert'?'emptyAlert':'emptyOutage'),tr(kind==='alert'?'emptyAlertDetail':'emptyOutageDetail')));
  function row(e) {
    const r=node('article','entry'),meta=node('div','meta caption-2');
    if(kind==='alert') {
      r.append(node('h4','title-3',attackName(e.type)),badge(tr(e.active?'active':'logged'),e.active?'bad':''));
      const point=e.type==='ARP 身分異常';
      meta.append(node('span','',point&&e.duration===0?clock(e.start):clock(e.start)+' → '+clock(e.last)),node('span','',point?tr('pointEvent'):e.duration<.1?tr('justDetected'):seconds(e.duration)));
    } else {
      const done=e.outcome==='recovered',stopped=e.outcome==='interrupted';
      r.append(node('h4','title-3',tr(done?'outageDone':stopped?'outageInterrupted':'outageOpen')),badge(tr(done?'restored':stopped?'notVerified':'awaitRecovery'),done?'good':stopped?'':'warning'));
      meta.append(node('span','',clock(e.start)+' → '+(done?clock(e.end):tr(stopped?'recordStopped':'awaitRecovery'))),node('span','',(e.start_known||stopped?'':'≥ ')+seconds(e.duration)));
      r.append(node('p','entry-note caption-2',tr('retryCount',{n:e.attempts})));
    }
    r.append(meta);return r;
  }
  items.slice(0,5).forEach(e=>fragment.append(row(e)));
  if(items.length>5){const d=document.createElement('details');d.append(node('summary','caption-1',tr('more',{n:items.length-5})));items.slice(5).forEach(e=>d.append(row(e)));fragment.append(d);}
  const open=$(id).querySelector('details')?.open;$(id).replaceChildren(fragment);$(id).dataset.signature=signature;if(open&&$(id).querySelector('details'))$(id).querySelector('details').open=true;
}
function commLabel(c,short=false) { const keys=short?{unknown:'routerUnknown',checking:'routerChecking',reachable:'routerOk',recovered:'routerRecovered',failed:'routerFailed',error:'routerError'}:{unknown:'unconfirmed',checking:'routerChecking',reachable:'commOk',recovered:'commRecovered',failed:'commFailed',error:'routerError'};return tr(keys[c]||'unconfirmed'); }
function connection(d,p) {
  const c=d.connection||{phase:'unknown',outages:[],total:0},phase=c.phase;
  const current=c.outages.find(e=>e.outcome==='open'),last=c.outages.find(e=>e.outcome==='recovered');
  const lost=phase==='down'||phase==='reconnecting',up=phase==='up'||phase==='recovered';
  let head='linkWaiting',detail=tr('linkUnknown'),tone='neutral';
  if(up){head='linkUp';detail=tr('linkStable');tone='good';}
  if(phase==='down'){head='linkDown';detail=tr('linkLost');tone='bad';}
  if(phase==='reconnecting'){head='linkRetry';detail=tr('retryDetail',{n:current?.attempts||0});tone='warning';}
  if(phase==='connecting'){head='linkConnecting';detail=tr('linkingDetail');tone='warning';}
  if(up&&p.communication==='failed'){head='commAffected';detail=tr('commAffectedDetail');tone='bad';}
  text('phaseLabel',tr({up:'connected',recovered:'restored',down:'disconnected',reconnecting:'reconnecting',connecting:'connecting'}[phase]||'unconfirmed'));
  $('phaseLabel').className='status-chip caption-3 '+(tone==='good'?'good':tone==='bad'?'bad':tone==='warning'?'warning':'');
  $('connectionPanel').dataset.tone=tone;text('connectionHeadline',tr(head));text('connectionDetail',detail);
  $('outageTimer').hidden=!lost||!current;text('duration',(current&&!current.start_known?'≥ ':'')+duration(current?.duration));
  text('routerStatus',lost||phase==='connecting'?tr('routerWait'):commLabel(p.communication,true));
  $('lastRecovery').hidden=!last||!up;
  if(last&&up){$('lastRecovery').replaceChildren(node('strong','body-2',tr('lastRecovery',{duration:seconds(last.duration)})),node('span','caption-2',tr('recoveryAt',{time:clock(last.end)})));}
  entries('outages',c.outages,'outage');text('outageCount',tr('count',{n:c.total}));return phase;
}
const ACTION_KEYS={locked:'guardLocked',repair:'guardRepair',rearm:'guardRearm',watch:'guardWatching',detected:'guardDetected',error:'guardError',invalid:'guardInvalid',waiting:'guardNetwork',garp_sent:'guardGarp',garp_error:'guardGarpError'};
function protection(p) {
  text('guardMode',!p.fresh?tr('waiting'):tr(p.mode==='on'?'guardOn':p.mode==='off'?'guardOff':'unconfirmed'));
  const affected=p.fresh&&p.mode==='on'&&p.action==='locked'&&p.communication==='failed';
  text('guardAction',!p.fresh?tr('guardWait'):tr(affected?'guardPartial':ACTION_KEYS[p.action]||'unconfirmed'));
  text('guardDetail',tr(!p.fresh?'guardNoData':p.mode==='off'?'guardOffDetail':affected?'guardPartialDetail':p.action==='locked'?'guardLockedDetail':'guardWatchDetail'));
  text('probeStatus',commLabel(p.communication));$('probeStatus').className='heading-6 '+(['reachable','recovered'].includes(p.communication)?'probe-good':p.communication==='failed'?'probe-bad':'');
  text('probeDetail',tr('checkDetail'));
  const history=document.createDocumentFragment();
  if(p.fresh&&p.mode==='on')history.append(node('p','body-3',tr('guardCounts',{repairs:p.repair_events||0,rearms:p.rearm_events||0})));
  for(const e of(p.actions||[]).slice(0,3)){const r=node('div','');r.append(node('span','',clock(e.time)),node('span','',(e.mode==='off'?tr('offPrefix'):'')+tr(ACTION_KEYS[e.kind||e.action]||'unconfirmed')));history.append(r);}$('guardHistory').replaceChildren(history);
  text('deviceIp',p.device_ip||'—');text('probeCounts',p.target?p.received+' / '+p.sent+' · '+p.target:'—');text('garpCount',(p.garp?.count||0)+' / '+(p.garp?.budget||12));
  text('wirelessDefense',!p.wireless_fresh?tr('unconfirmed'):tr(p.wireless?.binding==='on'?'bound':'unbound'));
  text('pmfPolicy',!p.wireless_fresh?tr('unconfirmed'):tr(p.wireless?.pmf==='required'?'pmfRequired':'pmfOptional'));
}
function render(d) {
  lastData=d;const recorded=d.presentation?.mode==='recorded';
  const phase=d.connection?.phase||'unknown',up=['up','recovered'].includes(phase);
  const p={fresh:false,mode:'unknown',action:'unknown',communication:'unknown',actions:[],...d.protection};
  if(!up){p.communication='unknown';p.fresh=false;}
  connection(d,p);protection(p);
  let title='watching',description=tr('watchingDetail'),tone='monitoring';
  if(d.state==='offline'){title='usbLost';description=tr('usbLostDetail');tone='warning';}
  else if(d.state==='stale'){title='stale';description=tr('staleDetail');tone='warning';}
  else if(d.state==='alert'){title='attackDetected';description=d.types.map(attackName).join(' · ');tone='alert';}
  else if(['down','reconnecting','connecting'].includes(phase)){title=phase==='down'?'linkDown':'linkRetry';description=tr('linkLost');tone='warning';}
  else if(p.communication==='failed'){title='commAffected';description=tr('commAffectedDetail');tone='warning';}
  else if(d.state==='waiting'){title='waitDevice';description=tr('waitDeviceDetail');tone='warning';}
  if(recorded&&d.presentation.finished){title='playbackEnd';description=tr('playbackEndDetail');tone='warning';}
  text('status',tr(title));text('description',description);$('statusMark').className='status-mark '+tone;
  window.dispatchEvent(new CustomEvent('swallow:state',{detail:{tone,paused:['offline','stale','waiting'].includes(d.state)||(recorded&&d.presentation.finished)}}));
  const fresh=d.serial&&d.age!==null&&d.age<5;$('live').className='live caption-1'+(fresh&&!recorded?' ok':'');text('liveText',tr(recorded?'recorded':fresh?'live':'waiting'));
  text('attack',d.types.length?d.types.map(attackName).join(' · '):tr(d.state==='monitoring'?'noAlert':'waiting'));
  const shown=visibleAlerts(d.display_events||d.events);entries('events',shown,'alert');text('alertCount',tr('count',{n:shown.length}));
  text('uart',tr(!d.serial?'disconnected':fresh?'usbReceiving':'usbWaiting'));
  text('session',tr('session',{time:clock(d.started)}));text('updated',tr('updated',{time:new Date().toLocaleTimeString(language==='en'?'en-GB':'zh-TW',{hour12:false})}));
  $('playback').hidden=!recorded;text('playback',recorded?tr('playback',{file:d.presentation.source,time:clock(d.presentation.time)}):'');
  $('error').hidden=!d.error;text('error',d.error||'');$('download').disabled=false;
}
function networkLost() {
  window.dispatchEvent(new CustomEvent('swallow:state',{detail:{tone:'warning',paused:true}}));
  text('status',tr('webLost'));text('description',tr('webLostDetail'));$('statusMark').className='status-mark warning';
  text('liveText',tr('waiting'));$('live').className='live caption-1';text('attack',tr('waiting'));
  connection({connection:{phase:'unknown',outages:lastData?.connection?.outages||[],total:lastData?.connection?.total||0}},{communication:'unknown'});
  protection({fresh:false,communication:'unknown',actions:[]});text('uart',tr('unconfirmed'));
  for(const chip of document.querySelectorAll('.entry .status-chip.bad,.entry .status-chip.warning')){chip.textContent=tr('lastRecord');chip.className='status-chip caption-3';}
  $('events').dataset.signature='';$('outages').dataset.signature='';
}
function setLanguage(next) {
  language=next;document.documentElement.lang=next==='en'?'en':'zh-Hant';document.title=tr('footer');
  document.querySelectorAll('[data-i18n]').forEach(e=>e.textContent=tr(e.dataset.i18n));document.querySelectorAll('[data-i18n-aria]').forEach(e=>e.setAttribute('aria-label',tr(e.dataset.i18nAria)));
  document.querySelectorAll('[data-lang]').forEach(e=>e.setAttribute('aria-pressed',String(e.dataset.lang===next)));
  try{localStorage.setItem('swallow-language',next);}catch(_){}
  if(lastData)render(lastData);if(fetchFailed)networkLost();
}
document.querySelectorAll('[data-lang]').forEach(e=>e.onclick=()=>setLanguage(e.dataset.lang));
$('download').onclick=()=>{if(!lastData)return;try{const blob=new Blob([JSON.stringify(lastData,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='esp32-records-'+new Date().toISOString().replace(/[:.]/g,'')+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(_){$('error').hidden=false;text('error',tr('exportError'));}};
async function update() {
  if(busy)return;busy=true;const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),4000);
  try{const r=await fetch('/api/status',{cache:'no-store',signal:controller.signal});if(!r.ok)throw Error(r.status);fetchFailed=false;render(await r.json());}catch(_){fetchFailed=true;networkLost();}finally{clearTimeout(timer);busy=false;}
}
setLanguage(language);update();setInterval(update,500);
