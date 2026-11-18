// Decorative only. This module never changes telemetry, labels or decisions.
const art=document.getElementById('watchArt');
const fallback=document.getElementById('rippleFallback');
const gpuCanvas=document.getElementById('shaderCanvas');
const toggle=document.getElementById('motionToggle');
const ctx=fallback.getContext('2d');
const reduced=matchMedia('(prefers-reduced-motion: reduce)');
let enabled=true,paused=false,visible=true,tone='monitoring',shader=null,epoch=0;
let raf=0,lastFrame=0,width=1,height=1,bursts=[],gpuAttempted=false;
try { enabled=localStorage.getItem('swallow-motion')!=='off'; } catch (_) {}
const palettes={monitoring:['#7ea690','#f6f7f8'],alert:['#bd736b','#f6f7f8'],warning:['#b69a63','#f6f7f8']};
function palette(){return palettes[tone]||palettes.monitoring;}
function moving(){return enabled&&!reduced.matches&&!paused&&visible&&!document.hidden;}
function draw(now=0){
  ctx.clearRect(0,0,width,height);ctx.fillStyle=palette()[1];ctx.fillRect(0,0,width,height);
  const time=moving()?now/1000:0;
  // The LAN HTTP fallback is intentionally small and capped at 30 fps.
  for(let i=0;i<4;i++){
    const phase=(time*.13+i/4)%1,radius=12+phase*Math.max(width*.6,height);
    ctx.globalAlpha=(1-phase)*.5;ctx.strokeStyle=palette()[0];ctx.lineWidth=1;
    ctx.beginPath();ctx.ellipse(width*.5,height*.5,radius,radius*.7,0,0,Math.PI*2);ctx.stroke();
  }
  bursts=bursts.filter(b=>now-b.time<1400);
  for(const b of bursts){const age=(now-b.time)/1400;ctx.globalAlpha=(1-age)*.65;ctx.lineWidth=1.5;ctx.beginPath();ctx.arc(b.x,b.y,6+age*90,0,Math.PI*2);ctx.stroke();}
  ctx.globalAlpha=1;
}
function frame(now){raf=0;if(!moving()||art.dataset.renderer==='webgpu')return;if(now-lastFrame>=1000/30){draw(now);lastFrame=now;}raf=requestAnimationFrame(frame);}
function loop(){if(!raf&&moving()&&art.dataset.renderer!=='webgpu')raf=requestAnimationFrame(frame);}
function useFallback(){gpuCanvas.hidden=true;fallback.hidden=false;art.dataset.renderer='canvas';loop();}
async function tryGpu(){
  if(gpuAttempted||!moving()||!window.isSecureContext||!navigator.gpu)return;
  gpuAttempted=true;const token=++epoch;
  try{
    const {mount}=await import('/assets/shader-engine.js');
    if(token!==epoch||!moving()){gpuAttempted=false;return;}
    // Both canvases stay in the layout so the shader can measure a real size.
    gpuCanvas.hidden=false;
    const instance=await mount(gpuCanvas,palette(),()=>{
      if(token!==epoch||!moving())return;
      art.dataset.renderer='webgpu';fallback.hidden=true;if(raf){cancelAnimationFrame(raf);raf=0;}
    },()=>{if(token===epoch)useFallback();});
    if(token!==epoch){instance.destroy();return;}
    shader=instance;
    if(instance.getFailureReason()){useFallback();return;}
    shader.resize(width,height);
    shader.update('waves',{colorA:palette()[0],colorB:palette()[1]});
    if(!moving())shader.pause();
  }catch(_){useFallback();}
}
function sync(){
  toggle.setAttribute('aria-pressed',String(enabled));art.dataset.motion=moving()?'on':'off';
  if(moving()){shader?.resume();loop();tryGpu();}
  else{shader?.pause();if(raf){cancelAnimationFrame(raf);raf=0;}bursts=[];draw(0);}
}
function resize(){
  const rect=art.getBoundingClientRect();width=rect.width;height=rect.height;
  const dpr=Math.min(devicePixelRatio||1,1.5);fallback.width=Math.round(width*dpr);fallback.height=Math.round(height*dpr);ctx.setTransform(dpr,0,0,dpr,0,0);draw(performance.now());
}
function ripple(event){
  if(!moving())return;const r=fallback.getBoundingClientRect();const box=art.getBoundingClientRect();
  bursts.push({x:event.clientX-(r.width?r.left:box.left),y:event.clientY-(r.height?r.top:box.top),time:performance.now()});
  if(bursts.length>8)bursts.shift();
}
art.addEventListener('pointerdown',e=>{if(e.target!==toggle)ripple(e);},{passive:true});
let lastPointer=0;art.addEventListener('pointermove',e=>{if(performance.now()-lastPointer>150){lastPointer=performance.now();ripple(e);}},{passive:true});
toggle.onclick=()=>{enabled=!enabled;try{localStorage.setItem('swallow-motion',enabled?'on':'off');}catch(_){}sync();};
window.addEventListener('swallow:state',event=>{
  const next=event.detail.tone||'monitoring';paused=!!event.detail.paused;
  if(next!==tone){tone=next;art.dataset.tone=tone;shader?.update('waves',{colorA:palette()[0],colorB:palette()[1]});draw(performance.now());}sync();
});
document.addEventListener('visibilitychange',sync);reduced.addEventListener('change',()=>{if(reduced.matches){epoch++;shader?.destroy();shader=null;gpuAttempted=false;useFallback();}sync();});
new ResizeObserver(resize).observe(art);
new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;sync();}).observe(art);
window.addEventListener('pagehide',()=>{epoch++;shader?.destroy();if(raf)cancelAnimationFrame(raf);raf=0;});
window.addEventListener('pageshow',event=>{if(event.persisted){shader=null;gpuAttempted=false;useFallback();sync();}});
art.dataset.renderer='canvas';resize();sync();
